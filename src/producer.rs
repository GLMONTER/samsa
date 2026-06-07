//! Client that sends records to a cluster.

use anyhow::anyhow;
use bytes::Bytes;
use std::{collections::HashMap, fmt::Debug, sync::Arc, time::Duration};
use tokio::{
    sync::mpsc::{Sender, UnboundedReceiver},
    sync::Mutex,
    task::{JoinHandle, JoinSet},
};
use tracing::instrument;

use crate::error::KafkaCode;
use crate::{
    error::{Error, Result},
    metadata::ClusterMetadata,
    network::BrokerConnection,
    protocol::{produce::request::Attributes, Header, ProduceRequest, ProduceResponse},
    DEFAULT_CLIENT_ID, DEFAULT_CORRELATION_ID,
};

const DEFAULT_REQUIRED_ACKS: i16 = 0;
const DEFAULT_TIMEOUT_MS: i32 = 1000;

#[derive(Clone)]
pub(crate) struct ProduceParams {
    pub correlation_id: i32,
    pub client_id: String,
    pub required_acks: i16,
    pub timeout_ms: i32,
}

impl ProduceParams {
    pub fn new() -> Self {
        Self {
            correlation_id: DEFAULT_CORRELATION_ID,
            client_id: DEFAULT_CLIENT_ID.to_owned(),
            required_acks: DEFAULT_REQUIRED_ACKS,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

pub struct Producer {
    pub sender: Sender<ProduceMessage>,
    pub receiver: UnboundedReceiver<Vec<Option<ProduceResponse>>>,
}

#[derive(Clone)]
pub struct ProduceMessage {
    pub key: Option<Bytes>,
    pub value: Option<Bytes>,
    pub headers: Vec<Header>,
    pub topic: String,
    pub partition_id: Option<i32>,
}

impl Producer {
    pub async fn produce(&self, message: ProduceMessage) {
        if self.sender.send(message).await.is_err() {
            tracing::warn!("Producer has hung up channel");
        }
    }
}

#[instrument(level = "debug", skip(messages, produce_params, cluster_metadata))]
pub(crate) async fn flush_producer<T: BrokerConnection + Clone + Debug + Send + 'static>(
    cluster_metadata: &ClusterMetadata<T>,
    produce_params: &ProduceParams,
    messages: Vec<ProduceMessage>,
    attributes: Attributes,
) -> Result<Vec<Option<ProduceResponse>>> {
    let mut brokers_and_messages = HashMap::new();
    tracing::debug!("Producing {} messages", messages.len());
    for message in messages {
        let partition_id = cluster_metadata.resolve_partition(
            &message.topic,
            &message.key,
            message.partition_id,
        )?;

        let broker_id = cluster_metadata
            .get_leader_id_for_topic_partition(&message.topic, partition_id)
            .ok_or(Error::NoLeaderForTopicPartition(
                message.topic.clone(),
                partition_id,
            ))?;

        match brokers_and_messages.get_mut(&broker_id) {
            None => {
                brokers_and_messages.insert(broker_id, vec![(message, partition_id)]);
            }
            Some(messages) => messages.push((message, partition_id)),
        };
    }

    let mut set = JoinSet::new();

    for (broker, messages) in brokers_and_messages.into_iter() {
        let broker_conn = cluster_metadata
            .broker_connections
            .get(&broker)
            .ok_or(Error::NoConnectionForBroker(broker))?
            .to_owned();
        let p = produce_params.clone();
        let a = attributes.clone();
        set.spawn(async move {
            produce(
                broker_conn,
                p.correlation_id,
                &p.client_id,
                p.required_acks,
                p.timeout_ms,
                &messages,
                a,
            )
            .await
        });
    }

    let mut responses = vec![];

    while let Some(res) = set.join_next().await {
        match res {
            Ok(produce_result) => {
                responses.push(produce_result?);
            }
            Err(join_error) if join_error.is_cancelled() => {
                tracing::warn!(
                    "producer task cancelled, client probably getting dropped: {:?}",
                    join_error
                );
                return Err(Error::TaskCancelled(
                    "producer task cancelled, client probably getting dropped".to_string(),
                ));
            }
            Err(join_error) if join_error.is_panic() => {
                tracing::error!("producer task panicked: {:?}", join_error);
                return Err(Error::TaskCancelled(format!(
                    "producer task panicked: {}",
                    join_error
                )));
            }
            Err(join_error) => {
                tracing::error!("producer task join error: {:?}", join_error);
                return Err(Error::TaskCancelled(format!(
                    "producer task join error: {}",
                    join_error
                )));
            }
        }
    }

    Ok(responses)
}

/// Produce messages to a broker.
///
/// See this [protocol spec](crate::prelude::protocol::produce) for more information.
pub async fn produce(
    mut broker_conn: impl BrokerConnection,
    correlation_id: i32,
    client_id: &str,
    required_acks: i16,
    timeout_ms: i32,
    messages: &Vec<(ProduceMessage, i32)>,
    attributes: Attributes,
) -> Result<Option<ProduceResponse>> {
    tracing::debug!("Producing {} messages", messages.len());

    let mut produce_request = ProduceRequest::new(
        required_acks,
        timeout_ms,
        correlation_id,
        client_id,
        attributes,
    );

    for (message, partition_id) in messages {
        produce_request.add(
            &message.topic,
            *partition_id,
            message.key.clone(),
            message.value.clone(),
            message.headers.clone(),
        );
    }

    broker_conn.send_request(&produce_request).await?;
    if required_acks > 0 {
        let response = ProduceResponse::try_from(broker_conn.receive_response().await?.freeze())?;
        Ok(Some(response))
    } else {
        Ok(None)
    }
}

pub struct SyncProducer<T: BrokerConnection> {
    cluster_metadata: Arc<Mutex<ClusterMetadata<T>>>,
    produce_params: ProduceParams,
    attributes: Attributes,
    /// Tracks when we last did an error-triggered metadata refresh so we don't
    /// hammer the broker with reconnects during an error storm.
    last_metadata_refresh: Arc<Mutex<std::time::Instant>>,
    /// Minimum time between error-triggered metadata refreshes. Configurable
    /// so callers can tune the tradeoff between refresh responsiveness and
    /// connection overhead during sustained error periods.
    min_metadata_refresh_interval: Duration,
    _keepalive_task: JoinHandle<()>,
}

impl<T: BrokerConnection + Clone + Debug + Send + Sync + 'static> SyncProducer<T> {
    pub async fn new(
        connection_params: T::ConnConfig,
        topics: Vec<String>,
        keepalive_interval: Duration,
        min_metadata_refresh_interval: Duration,
    ) -> Result<Self> {
        let cluster_metadata = Arc::new(Mutex::new(
            ClusterMetadata::<T>::new(
                connection_params,
                DEFAULT_CORRELATION_ID,
                DEFAULT_CLIENT_ID.to_owned(),
                topics,
            )
            .await?,
        ));

        let produce_params = ProduceParams::new();
        let attributes = Attributes::new(None);

        let metadata_clone = Arc::clone(&cluster_metadata);
        let keepalive_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(keepalive_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;
                let mut metadata = metadata_clone.lock().await;

                let broker_ids_before: Vec<i32> =
                    metadata.broker_connections.keys().copied().collect();

                if let Some((_id, conn)) = metadata.broker_connections.iter().next() {
                    let conn_clone = conn.clone();
                    match metadata.fetch(conn_clone).await {
                        Err(e) => {
                            //don't sync on fetch failure, existing connections
                            //are still valid, no need to rebuild them.
                            log::error!("broker metadata refresh failed: {}", e);
                        }
                        Ok(()) => {
                            //only sync (open new TLS connections) if the broker
                            //set actually changed.
                            let broker_ids_after: Vec<i32> =
                                metadata.brokers.iter().map(|b| b.node_id).collect();

                            let topology_changed = broker_ids_after
                                .iter()
                                .any(|id| !broker_ids_before.contains(id))
                                || broker_ids_before
                                    .iter()
                                    .any(|id| !broker_ids_after.contains(id));

                            if topology_changed {
                                log::info!("queue topology changed, resyncing connections");
                                if let Err(e) = metadata.sync().await {
                                    log::error!("failed to resync connections: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            cluster_metadata,
            produce_params,
            attributes,
            last_metadata_refresh: Arc::new(Mutex::new(
                //set far enough in the past that the first error always
                //triggers a refresh immediately.
                std::time::Instant::now()
                    .checked_sub(min_metadata_refresh_interval * 2)
                    .unwrap_or(std::time::Instant::now()),
            )),
            min_metadata_refresh_interval,
            _keepalive_task: keepalive_task,
        })
    }

    /// Set the correlation ID for requests.
    pub fn correlation_id(mut self, correlation_id: i32) -> Self {
        self.produce_params.correlation_id = correlation_id;
        self
    }

    /// Set the client ID for requests.
    pub fn client_id(mut self, client_id: String) -> Self {
        self.produce_params.client_id = client_id;
        self
    }

    /// Set the number of acknowledgments required.
    /// * 0 - no acknowledgments
    /// * 1 - leader only
    /// * -1 - full ISR
    pub fn required_acks(mut self, required_acks: i16) -> Self {
        self.produce_params.required_acks = required_acks;
        self
    }

    /// Set the timeout for awaiting a response (in milliseconds).
    pub fn timeout_ms(mut self, timeout_ms: i32) -> Self {
        self.produce_params.timeout_ms = timeout_ms;
        self
    }

    /// Set the compression algorithm.
    pub fn compression(mut self, algo: crate::prelude::Compression) -> Self {
        self.attributes.compression = Some(algo);
        self
    }

    /// Refresh metadata only if we haven't done so recently.
    /// Prevents an error storm from opening a flood of new TLS connections
    /// to every broker on every failed message.
    async fn maybe_refresh_metadata(&self) {
        let mut last = self.last_metadata_refresh.lock().await;
        if last.elapsed() < self.min_metadata_refresh_interval {
            tracing::debug!(
                "skipping metadata refresh, last refresh was {:?} ago",
                last.elapsed()
            );
            return;
        }
        *last = std::time::Instant::now();
        //release the refresh-time lock before acquiring the heavier metadata lock.
        drop(last);

        let mut metadata = self.cluster_metadata.lock().await;
        Self::refresh_metadata(&mut metadata).await;
    }

    async fn refresh_metadata(metadata: &mut ClusterMetadata<T>) {
        if let Some((_id, conn)) = metadata.broker_connections.iter().next() {
            let conn_clone = conn.clone();
            if let Err(e) = metadata.fetch(conn_clone).await {
                log::error!("broker metadata refresh failed: {}", e);
            }
            if let Err(e) = metadata.sync().await {
                log::error!("failed to resync connections: {}", e);
            }
        }
    }

    pub async fn produce_batch(&self, messages: Vec<ProduceMessage>) -> anyhow::Result<()> {
        if messages.is_empty() {
            return Ok(());
        }

        // Snapshot the metadata and release the lock before doing any network
        // I/O. Multiple callers can then pipeline sends concurrently rather than
        // serialising through a mutex held across the full network round trip.
        let (metadata_snapshot, produce_params, attributes) = {
            let metadata = self.cluster_metadata.lock().await;
            (
                metadata.clone(),
                self.produce_params.clone(),
                self.attributes.clone(),
            )
        };

        let result = tokio::time::timeout(Duration::from_secs(60), async {
            match flush_producer(&metadata_snapshot, &produce_params, messages, attributes).await {
                Ok(responses) => {
                    for response_opt in responses {
                        if let Some(response) = response_opt {
                            for topic_response in response.responses.iter() {
                                for partition_response in topic_response.partition_responses.iter()
                                {
                                    if partition_response.error_code != KafkaCode::None {
                                        return Err(anyhow!(
                                            "failed to send batch: {:?}",
                                            partition_response.error_code
                                        ));
                                    }
                                }
                            }
                        }
                    }
                    Ok(())
                }
                Err(e) => Err(anyhow!("failed to send batch: {}", e)),
            }
        })
        .await
        .map_err(|_| anyhow!("batch operation timed out"))?;

        if result.is_err() {
            //throttled refresh, won't hammer the broker if errors are sustained
            //but will refresh promptly on the first error.
            self.maybe_refresh_metadata().await;
        }

        result
    }

    pub async fn produce(&self, message: ProduceMessage) -> anyhow::Result<()> {
        //same snapshot pattern, release the lock before network I/O.
        let (metadata_snapshot, produce_params, attributes) = {
            let metadata = self.cluster_metadata.lock().await;
            (
                metadata.clone(),
                self.produce_params.clone(),
                self.attributes.clone(),
            )
        };

        let result = tokio::time::timeout(Duration::from_secs(10), async {
            match flush_producer(
                &metadata_snapshot,
                &produce_params,
                vec![message],
                attributes,
            )
            .await
            {
                Ok(responses) => {
                    for response_opt in responses {
                        if let Some(response) = response_opt {
                            for topic_response in response.responses.iter() {
                                for partition_response in topic_response.partition_responses.iter()
                                {
                                    if partition_response.error_code != KafkaCode::None {
                                        return Err(anyhow!(
                                            "failed to send message: {:?}",
                                            partition_response.error_code
                                        ));
                                    }
                                }
                            }
                        }
                    }
                    Ok(())
                }
                Err(e) => Err(anyhow!("failed to send message: {}", e)),
            }
        })
        .await
        .map_err(|_| anyhow!("send operation timed out"))?;

        if result.is_err() {
            self.maybe_refresh_metadata().await;
        }

        result
    }
}

impl<T: BrokerConnection> Drop for SyncProducer<T> {
    fn drop(&mut self) {
        self._keepalive_task.abort();
    }
}

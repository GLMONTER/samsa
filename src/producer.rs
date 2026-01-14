//! Client that sends records to a cluster.

use std::{collections::HashMap, fmt::Debug, sync::Arc, time::Duration};

use bytes::Bytes;
use tokio::{
    sync::mpsc::{Sender, UnboundedReceiver},
    sync::Mutex,
    task::{JoinHandle, JoinSet},
};
use tracing::instrument;

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

/// Kafka/Redpanda Producer.
///
/// This struct is a broker to a background worker that
/// does the actual producing. The background worker's job is to
/// collect incoming messages in a queue. When the queue fills up,
/// the messages are flushed. If the queue takes longer than a given
/// time to fill up, the messages are flushed. These two configurable
/// parameters found in the [`ProducerBuilder`](crate::prelude::ProducerBuilder) help dial in latency and throughput.
///
/// ### Example
/// ```rust
/// use samsa::prelude::*;
///
/// let bootstrap_addrs = vec![BrokerAddress {
///         host: "127.0.0.1".to_owned(),
///         port: 9092,
///     }];
/// let topic_name = "my-topic".to_string();
/// let partition_id = 0;
///
/// // create a stream of 5k messages in batches of 100
/// let stream = iter(0..5000).map(|_| ProduceMessage {
///     topic: topic_name.to_string(),
///     partition_id,
///     key: Some(bytes::Bytes::from_static(b"Tester")),
///     value: Some(bytes::Bytes::from_static(b"Value")),
///     headers: vec![
///         Header::new(String::from("Key"), bytes::Bytes::from("Value"))
///     ],
/// }).chunks(100);
///
/// let output_stream =
/// ProducerBuilder::<TcpConnection>::new(bootstrap_addrs, vec![topic_name.to_string()])
///     .await?
///     .batch_timeout_ms(1000)
///     .max_batch_size(100)
///     .clone()
///     .build_from_stream(stream)
///     .await;
///
/// tokio::pin!(output_stream);
/// while (output_stream.next().await).is_some() {}
/// ```
pub struct Producer {
    /// Direct connection to the background worker.
    pub sender: Sender<ProduceMessage>,
    /// Responses of the
    pub receiver: UnboundedReceiver<Vec<Option<ProduceResponse>>>,
}

/// Common produce message format.
#[derive(Clone)]
pub struct ProduceMessage {
    pub key: Option<Bytes>,
    pub value: Option<Bytes>,
    pub headers: Vec<Header>,
    pub topic: String,
    pub partition_id: i32,
}

impl Producer {
    pub async fn produce(&self, message: ProduceMessage) {
        if self.sender.send(message).await.is_err() {
            tracing::warn!("Producer has hung up channel");
        }
    }
}

// vector for the results from each broker
#[instrument(skip(messages, produce_params, cluster_metadata))]
pub(crate) async fn flush_producer<T: BrokerConnection + Clone + Debug + Send + 'static>(
    cluster_metadata: &ClusterMetadata<T>,
    produce_params: &ProduceParams,
    messages: Vec<ProduceMessage>,
    attributes: Attributes,
) -> Result<Vec<Option<ProduceResponse>>> {
    let mut brokers_and_messages = HashMap::new();
    tracing::debug!("Producing {} messages", messages.len());
    for message in messages {
        let broker_id = cluster_metadata
            .get_leader_id_for_topic_partition(&message.topic, message.partition_id)
            .ok_or(Error::NoLeaderForTopicPartition(
                message.topic.clone(),
                message.partition_id,
            ))?;

        match brokers_and_messages.get_mut(&broker_id) {
            None => {
                brokers_and_messages.insert(broker_id, vec![message]);
            }
            Some(messages) => messages.push(message),
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
    messages: &Vec<ProduceMessage>,
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

    for message in messages {
        produce_request.add(
            &message.topic,
            message.partition_id,
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

/// Synchronous producer that provides direct error handling.
///
/// Unlike the standard [`Producer`], this producer sends messages immediately
/// and returns errors directly, rather than batching and using a background worker.
/// It also maintains a background metadata refresh task to keep connections healthy.
///
/// ### Example
/// ```rust
/// use samsa::prelude::*;
///
/// let producer = SyncProducer::<TlsConnection>::new(
///     TlsConnectionOptions {
///         broker_options: vec![BrokerAddress {
///             host: "127.0.0.1".to_owned(),
///             port: 9092,
///         }],
///         key: "/path_to_key".into(),
///         cert: "/path_to_cert".into(),
///         cafile: Some("/path_to_ca".into()),
///     },
///     vec!["my-topic".to_string()],
///     10, // refresh metadata every 10 seconds
/// )
/// .await?;
///
/// let message = ProduceMessage {
///     topic: "my-topic".to_string(),
///     partition_id: 0,
///     key: Some(bytes::Bytes::from_static(b"key")),
///     value: Some(bytes::Bytes::from_static(b"value")),
///     headers: vec![],
/// };
///
/// let result = producer.produce(message).await?;
/// ```
pub struct SyncProducer<T: BrokerConnection> {
    cluster_metadata: Arc<Mutex<ClusterMetadata<T>>>,
    produce_params: ProduceParams,
    attributes: Attributes,
    _keepalive_task: JoinHandle<()>,
}

impl<T: BrokerConnection + Clone + Debug + Send + Sync + 'static> SyncProducer<T> {
    /// Create a new synchronous producer with automatic metadata refresh.
    ///
    /// # Arguments
    /// * `connection_params` - Connection configuration for the broker
    /// * `topics` - List of topics this producer will send to
    /// * `keepalive_interval_secs` - How often to refresh metadata (in seconds)
    pub async fn new(
        connection_params: T::ConnConfig,
        topics: Vec<String>,
        keepalive_interval_secs: u64,
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

        // Spawn keepalive task
        let metadata_clone = Arc::clone(&cluster_metadata);
        let keepalive_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(keepalive_interval_secs));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;
                let mut metadata = metadata_clone.lock().await;

                if let Some((_id, conn)) = metadata.broker_connections.iter().next() {
                    let conn_clone = conn.clone();
                    if let Err(e) = metadata.fetch(conn_clone).await {
                        log::error!(
                            "broker metadata refresh failed: {:?}, attempting resync",
                            e
                        );
                        if let Err(sync_err) = metadata.sync().await {
                            log::error!("failed to resync connections: {:?}", sync_err);
                        } else {
                            log::info!("successfully resynced connections");
                        }
                    }
                }
            }
        });

        Ok(Self {
            cluster_metadata,
            produce_params,
            attributes,
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

    /// Produce a message and wait for the result.
    ///
    /// This sends the message immediately and returns the broker's response or error.
    pub async fn produce(
        &self,
        message: ProduceMessage,
    ) -> Result<Vec<Option<ProduceResponse>>> {
        let metadata = self.cluster_metadata.lock().await;
        flush_producer(&*metadata, &self.produce_params, vec![message], self.attributes.clone())
            .await
    }

    /// Produce multiple messages in a single batch.
    pub async fn produce_batch(
        &self,
        messages: Vec<ProduceMessage>,
    ) -> Result<Vec<Option<ProduceResponse>>> {
        let metadata = self.cluster_metadata.lock().await;
        flush_producer(&*metadata, &self.produce_params, messages, self.attributes.clone()).await
    }
}

impl<T: BrokerConnection> Drop for SyncProducer<T> {
    fn drop(&mut self) {
        self._keepalive_task.abort();
    }
}

use std::fmt::Debug;
use std::time::Duration;

use tokio::sync::mpsc::{channel, unbounded_channel, Receiver, UnboundedSender};
use tokio_stream::{Stream, StreamExt};

use crate::network::BrokerConnection;
use crate::prelude::Compression;
use crate::producer::{flush_producer, ProduceMessage, ProduceParams, Producer};
use crate::protocol::produce::request::Attributes;
use crate::protocol::ProduceResponse;
use crate::DEFAULT_CORRELATION_ID;
use crate::{error::Result, metadata::ClusterMetadata, DEFAULT_CLIENT_ID};

const DEFAULT_MAX_BATCH_SIZE: usize = 100;
const DEFAULT_BATCH_TIMEOUT_MS: u64 = 1000;
const DEFAULT_METADATA_REFRESH_INTERVAL: Duration = Duration::from_secs(300);
const DEFAULT_MIN_METADATA_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct ProducerBuilder<T: BrokerConnection> {
    cluster_metadata: ClusterMetadata<T>,
    produce_params: ProduceParams,
    max_batch_size: usize,
    batch_timeout_ms: u64,
    attributes: Attributes,
    /// How often the background task proactively refreshes cluster metadata
    /// even when there are no errors. Keeps partition leader info fresh across
    /// broker restarts. Default: 5 minutes.
    metadata_refresh_interval: Duration,
    /// Minimum time between error-triggered metadata refreshes. Prevents an
    /// error storm from opening a flood of new TLS connections to every broker.
    /// Default: 5 seconds.
    min_metadata_refresh_interval: Duration,
}

impl<T> ProducerBuilder<T>
where
    T: BrokerConnection + Clone + Debug + Send + Sync + 'static,
{
    pub async fn new(connection_params: T::ConnConfig, topics: Vec<String>) -> Result<Self> {
        let cluster_metadata = ClusterMetadata::new(
            connection_params,
            DEFAULT_CORRELATION_ID,
            DEFAULT_CLIENT_ID.to_owned(),
            topics,
        )
        .await?;

        Ok(Self {
            cluster_metadata,
            produce_params: ProduceParams::new(),
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
            batch_timeout_ms: DEFAULT_BATCH_TIMEOUT_MS,
            attributes: Attributes::new(None),
            metadata_refresh_interval: DEFAULT_METADATA_REFRESH_INTERVAL,
            min_metadata_refresh_interval: DEFAULT_MIN_METADATA_REFRESH_INTERVAL,
        })
    }

    /// The max number of messages that will sit in queue to be produced.
    ///
    /// When the queue size surpasses this number, the queue will be flushed and
    /// all records produced. Unless the [`batch_timeout_ms`](Self::batch_timeout_ms) has passed, then the
    /// queue will be flushed regardless of its size.
    ///
    /// Increasing this number will increase latency, but also increase throughput.
    pub fn max_batch_size(&mut self, max_batch_size: usize) -> &mut Self {
        self.max_batch_size = max_batch_size;
        self
    }

    /// The maximum time a message will sit in the queue to be produced.
    ///
    /// Each batch will wait a maximum of this time, and then be flushed.
    /// If the batch fills up with [`max_batch_size`](Self::max_batch_size) then it will be flushed
    /// before this time runs out.
    ///
    /// Decreasing this number will lower latency, but also lower throughput.
    pub fn batch_timeout_ms(&mut self, batch_timeout_ms: u64) -> &mut Self {
        self.batch_timeout_ms = batch_timeout_ms;
        self
    }

    pub fn correlation_id(&mut self, correlation_id: i32) -> &mut Self {
        self.produce_params.correlation_id = correlation_id;
        self
    }

    pub fn client_id(mut self, client_id: String) -> Self {
        self.produce_params.client_id = client_id;
        self
    }

    /// The number of acknowledgments the producer requires the leader to have received before considering a request complete. Allowed values: 0 for no acknowledgments, 1 for only the leader and -1 for the full ISR.
    pub fn required_acks(&mut self, required_acks: i16) -> &mut Self {
        self.produce_params.required_acks = required_acks;
        self
    }

    /// The timeout to await a response in milliseconds.
    pub fn timeout_ms(&mut self, timeout_ms: i32) -> &mut Self {
        self.produce_params.timeout_ms = timeout_ms;
        self
    }

    pub fn compression(&mut self, algo: Compression) -> &mut Self {
        self.attributes.compression = Some(algo);
        self
    }

    /// How often to proactively refresh cluster metadata in the background.
    /// Lower values mean faster recovery after a broker restart at the cost of
    /// more metadata fetches. Default: 5 minutes.
    pub fn metadata_refresh_interval(&mut self, interval: Duration) -> &mut Self {
        self.metadata_refresh_interval = interval;
        self
    }

    /// Minimum time between error-triggered metadata refreshes. Prevents
    /// sustained errors from hammering the broker with reconnects. Default: 5s.
    pub fn min_metadata_refresh_interval(&mut self, interval: Duration) -> &mut Self {
        self.min_metadata_refresh_interval = interval;
        self
    }

    pub async fn build(self) -> Producer {
        let (input_sender, input_receiver) = channel(self.max_batch_size);
        let (output_sender, output_receiver) = unbounded_channel();

        let produce_stream = into_produce_stream(input_receiver).chunks_timeout(
            self.max_batch_size,
            Duration::from_millis(self.batch_timeout_ms),
        );

        tokio::spawn(producer(
            produce_stream,
            output_sender,
            self.cluster_metadata,
            self.produce_params,
            self.attributes,
            self.metadata_refresh_interval,
            self.min_metadata_refresh_interval,
        ));

        Producer {
            sender: input_sender,
            receiver: output_receiver,
        }
    }

    pub async fn build_from_stream(
        self,
        stream: impl Stream<Item = Vec<ProduceMessage>> + std::marker::Send + 'static,
    ) -> impl Stream<Item = Vec<Option<ProduceResponse>>> {
        let (output_sender, mut output_receiver) = unbounded_channel();

        tokio::spawn(producer(
            stream,
            output_sender,
            self.cluster_metadata,
            self.produce_params,
            self.attributes,
            self.metadata_refresh_interval,
            self.min_metadata_refresh_interval,
        ));

        async_stream::stream! {
            while let Some(message) = output_receiver.recv().await {
                yield message;
            }
        }
    }
}

fn into_produce_stream(
    mut receiver: Receiver<ProduceMessage>,
) -> impl Stream<Item = ProduceMessage> {
    async_stream::stream! {
        while let Some(message) = receiver.recv().await {
            yield message;
        }
    }
}

async fn producer<T: BrokerConnection + Clone + Debug + Send + 'static>(
    stream: impl Stream<Item = Vec<ProduceMessage>> + Send + 'static,
    output_sender: UnboundedSender<Vec<Option<ProduceResponse>>>,
    mut cluster_metadata: ClusterMetadata<T>,
    produce_params: ProduceParams,
    attributes: Attributes,
    metadata_refresh_interval: Duration,
    min_metadata_refresh_interval: Duration,
) {
    tokio::pin!(stream);

    let mut metadata_refresh_ticker = tokio::time::interval(metadata_refresh_interval);
    metadata_refresh_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Don't refresh immediately on start — we just fetched metadata in new()
    metadata_refresh_ticker.reset();

    let mut last_error_refresh = std::time::Instant::now()
        .checked_sub(min_metadata_refresh_interval * 2)
        .unwrap_or(std::time::Instant::now());

    loop {
        tokio::select! {
            _ = metadata_refresh_ticker.tick() => {
                // Proactive background refresh — only syncs if topology changed,
                // matching the behaviour in the fixed metadata.rs
                if let Some((_id, conn)) = cluster_metadata.broker_connections.iter().next() {
                    let conn_clone = conn.clone();
                    let broker_ids_before: Vec<i32> =
                        cluster_metadata.broker_connections.keys().copied().collect();

                    match cluster_metadata.fetch(conn_clone).await {
                        Err(e) => log::error!("background metadata refresh failed: {}", e),
                        Ok(()) => {
                            let broker_ids_after: Vec<i32> =
                                cluster_metadata.brokers.iter().map(|b| b.node_id).collect();
                            let topology_changed = broker_ids_after
                                .iter()
                                .any(|id| !broker_ids_before.contains(id))
                                || broker_ids_before
                                    .iter()
                                    .any(|id| !broker_ids_after.contains(id));
                            if topology_changed {
                                log::info!("queue topology changed, resyncing connections");
                                if let Err(e) = cluster_metadata.sync().await {
                                    log::error!("failed to resync connections: {}", e);
                                }
                            }
                        }
                    }
                }
            }

            result = stream.next() => {
                match result {
                    Some(messages) => {
                        match flush_producer(
                            &cluster_metadata,
                            &produce_params,
                            messages,
                            attributes.clone(),
                        )
                        .await
                        {
                            Err(err) => {
                                log::error!("failed to produce message {:?}", err);
                                //throttled error-triggered refresh
                                if last_error_refresh.elapsed() >= min_metadata_refresh_interval {
                                    last_error_refresh = std::time::Instant::now();
                                    if let Some((_id, conn)) = cluster_metadata.broker_connections.iter().next() {
                                        let conn_clone = conn.clone();
                                        if let Err(e) = cluster_metadata.fetch(conn_clone).await {
                                            log::error!("error-triggered metadata refresh failed: {}", e);
                                        } else if let Err(e) = cluster_metadata.sync().await {
                                            log::error!("error-triggered metadata sync failed: {}", e);
                                        }
                                    }
                                }
                            }
                            Ok(r) => {
                                if let Err(err) = output_sender.send(r) {
                                    tracing::error!("Error sending results from producer agent {:?}", err);
                                }
                            }
                        }
                    }
                    None => break,
                }
            }
        }
    }
}

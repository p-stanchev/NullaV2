use async_trait::async_trait;
use futures::prelude::*;
use libp2p::request_response;
use libp2p::swarm::StreamProtocol;
use std::io;

use crate::protocol;

pub const PROTOCOL_NAME: &str = "/nulla/reqres/1";

// SECURITY: Maximum message sizes to prevent memory exhaustion attacks
// These limits prevent attackers from sending oversized messages that could exhaust node memory
const REQUEST_SIZE_MAXIMUM: u64 = protocol::MAX_MESSAGE_SIZE as u64;  // 16 MB
const RESPONSE_SIZE_MAXIMUM: u64 = protocol::MAX_MESSAGE_SIZE as u64; // 16 MB

#[derive(Clone, Default)]
pub struct NullaCodec;

#[async_trait]
impl request_response::Codec for NullaCodec {
    type Protocol = StreamProtocol;
    type Request = protocol::Req;
    type Response = protocol::Resp;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.take(REQUEST_SIZE_MAXIMUM).read_to_end(&mut buf).await?;

        // SECURITY: Check size before deserialization
        if buf.len() > protocol::MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Request too large: {} bytes (max {})", buf.len(), protocol::MAX_MESSAGE_SIZE)
            ));
        }

        bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.take(RESPONSE_SIZE_MAXIMUM).read_to_end(&mut buf).await?;

        // SECURITY: Check size before deserialization
        if buf.len() > protocol::MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Response too large: {} bytes (max {})", buf.len(), protocol::MAX_MESSAGE_SIZE)
            ));
        }

        bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = bincode::serialize(&req).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        if data.len() > REQUEST_SIZE_MAXIMUM as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request too large",
            ));
        }
        io.write_all(&data).await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data =
            bincode::serialize(&resp).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        if data.len() > RESPONSE_SIZE_MAXIMUM as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response too large",
            ));
        }
        io.write_all(&data).await?;
        Ok(())
    }
}

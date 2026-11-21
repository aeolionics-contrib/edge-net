use core::fmt::Display;
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use edge_nal::{
    MulticastV4, MulticastV6, Readable, UdpBind, UdpReceive, UdpSend, UdpSplit, UdpSplitMulticast,
};

use embassy_net::error::Full;
use embassy_net::udp::{BindError, RecvError, SendError};
use embassy_net::Stack;

use embedded_io_async::{ErrorKind, ErrorType};

use crate::{to_emb_bind_socket, to_emb_socket, to_net_socket};

/// A type that implements the `UdpBind` factory trait from `edge-nal`.
/// Uses the provided Embassy networking stack to create UDP sockets.
///
/// The type is `Copy` and `Clone`, so it can be easily passed around.
#[derive(Copy, Clone)]
pub struct Udp<'d> {
    /// The Embassy networking stack to use for creating UDP sockets.
    stack: Stack<'d>,
}

impl<'d> Udp<'d> {
    /// The stack's UDP sockets. On xarxa they hold no buffers of their own:
    /// datagrams wait in the stack's packet pool, and the number of sockets is
    /// xarxa's `udp-socket-count-N`.
    pub fn new(stack: Stack<'d>) -> Self {
        Self { stack }
    }
}

impl<'d> UdpBind for Udp<'d> {
    type Error = UdpError;

    // The stack's lifetime, not the borrow's: on xarxa a `Stack<'d>` is
    // invariant in `'d`.
    type Socket<'a>
        = UdpSocket<'d>
    where
        Self: 'a;

    async fn bind(&self, local: SocketAddr) -> Result<Self::Socket<'_>, Self::Error> {
        let mut socket = UdpSocket::new(self.stack)?;

        socket.socket.bind(
            to_emb_bind_socket(local).ok_or(UdpError::UnsupportedProto)?,
            embassy_net::wire::ListenSocketAddr::UNSPECIFIED,
        )?;

        Ok(socket)
    }
}

/// A UDP socket.
/// Implements the `UdpReceive` `UdpSend` and `UdpSplit` traits from `edge-nal`.
pub struct UdpSocket<'d> {
    /// The Embassy networking stack.
    #[allow(unused)]
    stack: embassy_net::Stack<'d>,
    /// The underlying Embassy UDP socket.
    socket: embassy_net::udp::UdpSocket<'d>,
}

impl<'d> UdpSocket<'d> {
    fn new(stack: Stack<'d>) -> Result<Self, UdpError> {
        Ok(Self {
            stack,
            socket: embassy_net::udp::UdpSocket::new(stack)?,
        })
    }

    /// Joins (or leaves) a group on the interfaces `interface` names: every
    /// interface if it is unspecified, else the ones that have it.
    #[cfg(feature = "multicast")]
    fn for_ifaces(
        &self,
        interface: Option<core::net::IpAddr>,
        mut f: impl FnMut(embassy_net::iface::Iface<'d>) -> Result<(), UdpError>,
    ) -> Result<(), UdpError> {
        let mut any = false;
        for iface in self.stack.ifaces() {
            if let Some(addr) = interface {
                if !iface.has_ip_addr(addr) {
                    continue;
                }
            }
            any = true;
            f(iface)?;
        }
        if any {
            Ok(())
        } else {
            Err(UdpError::MulticastUnaddressable)
        }
    }

    async fn join_v4(
        &self,
        #[allow(unused)] multicast_addr: Ipv4Addr,
        #[allow(unused)] interface: Ipv4Addr,
    ) -> Result<(), UdpError> {
        #[cfg(feature = "multicast")]
        {
            let group = crate::to_emb_addr(core::net::IpAddr::V4(multicast_addr))
                .ok_or(UdpError::UnsupportedProto)?;
            // The interfaces holding `interface`, or every interface if it
            // is unspecified.
            let interface =
                (!interface.is_unspecified()).then_some(core::net::IpAddr::V4(interface));
            self.for_ifaces(interface, |iface| Ok(iface.join_multicast_group(group)?))?;
        }

        #[cfg(not(feature = "multicast"))]
        {
            Err(UdpError::UnsupportedProto)?;
        }

        Ok(())
    }

    async fn leave_v4(
        &self,
        #[allow(unused)] multicast_addr: Ipv4Addr,
        #[allow(unused)] interface: Ipv4Addr,
    ) -> Result<(), UdpError> {
        #[cfg(feature = "multicast")]
        {
            let group = crate::to_emb_addr(core::net::IpAddr::V4(multicast_addr))
                .ok_or(UdpError::UnsupportedProto)?;
            // The interfaces holding `interface`, or every interface if it
            // is unspecified.
            let interface =
                (!interface.is_unspecified()).then_some(core::net::IpAddr::V4(interface));
            self.for_ifaces(interface, |iface| Ok(iface.leave_multicast_group(group)?))?;
        }

        #[cfg(not(feature = "multicast"))]
        {
            Err(UdpError::UnsupportedProto)?;
        }

        Ok(())
    }

    async fn join_v6(
        &self,
        #[allow(unused)] multicast_addr: Ipv6Addr,
        _interface: u32,
    ) -> Result<(), UdpError> {
        #[cfg(feature = "multicast")]
        {
            let group = crate::to_emb_addr(core::net::IpAddr::V6(multicast_addr))
                .ok_or(UdpError::UnsupportedProto)?;
            // IPv6 names the interface by index, which xarxa has no use
            // for: every interface.
            self.for_ifaces(None, |iface| Ok(iface.join_multicast_group(group)?))?;
        }

        #[cfg(not(feature = "multicast"))]
        {
            Err(UdpError::UnsupportedProto)?;
        }

        Ok(())
    }

    async fn leave_v6(
        &self,
        #[allow(unused)] multicast_addr: Ipv6Addr,
        _interface: u32,
    ) -> Result<(), UdpError> {
        #[cfg(feature = "multicast")]
        {
            let group = crate::to_emb_addr(core::net::IpAddr::V6(multicast_addr))
                .ok_or(UdpError::UnsupportedProto)?;
            // IPv6 names the interface by index, which xarxa has no use
            // for: every interface.
            self.for_ifaces(None, |iface| Ok(iface.leave_multicast_group(group)?))?;
        }

        #[cfg(not(feature = "multicast"))]
        {
            Err(UdpError::UnsupportedProto)?;
        }

        Ok(())
    }
}

impl Drop for UdpSocket<'_> {
    fn drop(&mut self) {
        self.socket.close();
    }
}

impl ErrorType for UdpSocket<'_> {
    type Error = UdpError;
}

impl UdpReceive for UdpSocket<'_> {
    async fn receive(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), Self::Error> {
        let (len, remote_endpoint) = self.socket.recv_from(buffer).await?;

        Ok((len, to_net_socket(remote_endpoint.remote_addr)))
    }
}

impl UdpSend for UdpSocket<'_> {
    async fn send(&mut self, remote: SocketAddr, data: &[u8]) -> Result<(), Self::Error> {
        self.socket
            .send_to(
                data,
                to_emb_socket(remote).ok_or(UdpError::UnsupportedProto)?,
            )
            .await?;

        Ok(())
    }
}

impl ErrorType for &UdpSocket<'_> {
    type Error = UdpError;
}

impl UdpReceive for &UdpSocket<'_> {
    async fn receive(&mut self, buffer: &mut [u8]) -> Result<(usize, SocketAddr), Self::Error> {
        let (len, remote_endpoint) = self.socket.recv_from(buffer).await?;

        Ok((len, to_net_socket(remote_endpoint.remote_addr)))
    }
}

impl UdpSend for &UdpSocket<'_> {
    async fn send(&mut self, remote: SocketAddr, data: &[u8]) -> Result<(), Self::Error> {
        self.socket
            .send_to(
                data,
                to_emb_socket(remote).ok_or(UdpError::UnsupportedProto)?,
            )
            .await?;

        Ok(())
    }
}

impl Readable for &UdpSocket<'_> {
    async fn readable(&mut self) -> Result<(), Self::Error> {
        self.socket.wait_recv_ready().await;
        Ok(())
    }
}

impl UdpSplit for UdpSocket<'_> {
    type Receive<'a>
        = &'a Self
    where
        Self: 'a;

    type Send<'a>
        = &'a Self
    where
        Self: 'a;

    fn split(&mut self) -> (Self::Receive<'_>, Self::Send<'_>) {
        (&*self, &*self)
    }
}

impl<'d> UdpSplitMulticast for UdpSocket<'d> {
    type MulticastV4<'a>
        = &'a Self
    where
        Self: 'a;

    type MulticastV6<'a>
        = &'a Self
    where
        Self: 'a;

    fn split_multicast(
        &mut self,
    ) -> (
        Self::Receive<'_>,
        Self::Send<'_>,
        Self::MulticastV4<'_>,
        Self::MulticastV6<'_>,
    ) {
        (&*self, &*self, &*self, &*self)
    }
}

impl MulticastV4 for UdpSocket<'_> {
    async fn join_v4(
        &mut self,
        multicast_addr: Ipv4Addr,
        interface: Ipv4Addr,
    ) -> Result<(), Self::Error> {
        Self::join_v4(self, multicast_addr, interface).await
    }

    async fn leave_v4(
        &mut self,
        multicast_addr: Ipv4Addr,
        interface: Ipv4Addr,
    ) -> Result<(), Self::Error> {
        Self::leave_v4(self, multicast_addr, interface).await
    }
}

impl MulticastV4 for &UdpSocket<'_> {
    async fn join_v4(
        &mut self,
        multicast_addr: Ipv4Addr,
        interface: Ipv4Addr,
    ) -> Result<(), Self::Error> {
        UdpSocket::join_v4(self, multicast_addr, interface).await
    }

    async fn leave_v4(
        &mut self,
        multicast_addr: Ipv4Addr,
        interface: Ipv4Addr,
    ) -> Result<(), Self::Error> {
        UdpSocket::leave_v4(self, multicast_addr, interface).await
    }
}

impl MulticastV6 for UdpSocket<'_> {
    async fn join_v6(
        &mut self,
        multicast_addr: Ipv6Addr,
        interface: u32,
    ) -> Result<(), Self::Error> {
        Self::join_v6(self, multicast_addr, interface).await
    }

    async fn leave_v6(
        &mut self,
        multicast_addr: Ipv6Addr,
        interface: u32,
    ) -> Result<(), Self::Error> {
        Self::leave_v6(self, multicast_addr, interface).await
    }
}

impl MulticastV6 for &UdpSocket<'_> {
    async fn join_v6(
        &mut self,
        multicast_addr: Ipv6Addr,
        interface: u32,
    ) -> Result<(), Self::Error> {
        UdpSocket::join_v6(self, multicast_addr, interface).await
    }

    async fn leave_v6(
        &mut self,
        multicast_addr: Ipv6Addr,
        interface: u32,
    ) -> Result<(), Self::Error> {
        UdpSocket::leave_v6(self, multicast_addr, interface).await
    }
}

impl Readable for UdpSocket<'_> {
    async fn readable(&mut self) -> Result<(), Self::Error> {
        self.socket.wait_recv_ready().await;
        Ok(())
    }
}

/// A shared error type that is used by the UDP factory trait implementation as well as the UDP socket
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum UdpError {
    /// An error occurred while receiving data.
    Recv(RecvError),
    /// An error occurred while sending data.
    Send(SendError),
    /// An error occurred while binding the socket.
    Bind(BindError),
    /// The table of joined multicast groups is already full.
    MulticastGroupTableFull,
    /// Cannot join/leave the given multicast group.
    MulticastUnaddressable,
    /// No more UDP socket buffers are available.
    NoBuffers,
    /// The provided protocol is not supported.
    UnsupportedProto,
}

impl From<Full> for UdpError {
    fn from(_: Full) -> Self {
        UdpError::NoBuffers
    }
}

impl From<RecvError> for UdpError {
    fn from(e: RecvError) -> Self {
        UdpError::Recv(e)
    }
}

impl From<SendError> for UdpError {
    fn from(e: SendError) -> Self {
        UdpError::Send(e)
    }
}

impl From<BindError> for UdpError {
    fn from(e: BindError) -> Self {
        UdpError::Bind(e)
    }
}

impl Display for UdpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            UdpError::Recv(e) => write!(f, "UDP receive error: {:?}", e),
            UdpError::Send(e) => write!(f, "UDP send error: {:?}", e),
            UdpError::Bind(e) => write!(f, "UDP bind error: {:?}", e),
            UdpError::MulticastGroupTableFull => {
                write!(f, "UDP multicast group table is full")
            }
            UdpError::MulticastUnaddressable => {
                write!(f, "UDP multicast address is unaddressable")
            }
            UdpError::NoBuffers => write!(f, "No UDP socket available"),
            UdpError::UnsupportedProto => write!(f, "Unsupported protocol"),
        }
    }
}

impl core::error::Error for UdpError {}

#[cfg(all(
    feature = "multicast",
    any(feature = "proto-ipv4", feature = "proto-ipv6")
))]
impl From<embassy_net::iface::MulticastError> for UdpError {
    fn from(e: embassy_net::iface::MulticastError) -> Self {
        match e {
            embassy_net::iface::MulticastError::TooManyGroups => UdpError::MulticastGroupTableFull,
            embassy_net::iface::MulticastError::Unaddressable => UdpError::MulticastUnaddressable,
        }
    }
}

impl embedded_io_async::Error for UdpError {
    fn kind(&self) -> ErrorKind {
        match self {
            UdpError::Recv(_) => ErrorKind::Other,
            UdpError::Send(_) => ErrorKind::Other,
            UdpError::Bind(_) => ErrorKind::Other,
            UdpError::MulticastGroupTableFull => ErrorKind::Other,
            UdpError::MulticastUnaddressable => ErrorKind::Other,
            UdpError::NoBuffers => ErrorKind::OutOfMemory,
            UdpError::UnsupportedProto => ErrorKind::InvalidInput,
        }
    }
}

#[cfg(test)]
mod test {
    use super::UdpSocket;

    #[test]
    fn socket_new_and_drop() {
        let (stack, _runner) = crate::test::stack();

        let Ok(socket) = UdpSocket::new(stack) else {
            panic!("socket creation failed");
        };

        // Dropping the socket gives its slot back to the stack
        drop(socket);
        assert!(UdpSocket::new(stack).is_ok());
    }
}

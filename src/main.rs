use anyhow::{bail, Result};
use dotenv::dotenv;
use log::{error, info, warn};
use std::io::Cursor;
use std::io::ErrorKind::{BrokenPipe, ConnectionAborted};
use std::net::SocketAddr;
use std::{env, io};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::{select};

enum PacketType {
    Auth,
    AuthResponse,
    ExecCommand,
    ResponseValue
}

impl Into<i32> for PacketType {
    fn into(self) -> i32 {
        match self {
            PacketType::Auth => 3,
            PacketType::AuthResponse => 2,
            PacketType::ExecCommand => 2,
            PacketType::ResponseValue => 0,
        }
    }
}

struct RconPacket {
    packet_id: i32,
    packet_type: i32,
    body: Vec<u8>
}

impl RconPacket {
    fn body_string(&self) -> Result<String> {
        let str = std::str::from_utf8(&self.body)?;
        Ok(str.to_string())
    }
}

#[derive(Error, Debug)]
enum RconError {
    #[error("invalid packet type received: {0}")]
    InvalidPacketType(i32),
    #[error("invalid password: {0}")]
    InvalidPassword(String)
}

async fn accept(rcon_password: &str, mut socket: TcpStream, socket_addr: SocketAddr) -> Result<()> {
    let mut buf = vec![0u8; 1500];
    socket.read(&mut buf).await?;
    auth(rcon_password, &mut socket, &buf).await?;

    info!("Authorized connection {}", socket_addr);

    loop {
        let bytes_read = socket.read(&mut buf).await?;
        if bytes_read == 0 {
            break Ok(());
        }
        
        let packet = read_packet(&buf).await?;

        if packet.packet_type == PacketType::ExecCommand.into() {
            let command = packet.body_string()?;
            info!("Command received from {}: {}", socket_addr, command);

            send_rcon(
                &mut socket,
                packet.packet_id,
                PacketType::ResponseValue,
                &"Command executed"
            ).await?;
        } else {
            warn!("Unknown packet received from {}: {}", socket_addr, packet.packet_type);
            send_rcon(
                &mut socket,
                packet.packet_id,
                PacketType::ResponseValue,
                &format!("Unknown packet type {}", packet.packet_type)
            ).await?;
        }
    }
}

async fn read_packet(packet: &[u8]) -> Result<RconPacket> {
    let mut cursor = Cursor::new(packet);

    let packet_size = cursor.read_i32_le().await?;
    let packet_id = cursor.read_i32_le().await?;
    let packet_type = cursor.read_i32_le().await?;

    let body_size = (packet_size - 10) as usize;
    let mut body = vec![0u8; body_size];
    cursor.read(&mut body).await?;

    Ok(
        RconPacket {
            packet_id,
            packet_type,
            body,
        }
    )
}

async fn auth(rcon_password: &str, socket: &mut TcpStream, packet: &[u8]) -> Result<()> {
    let packet = read_packet(packet).await?;

    if packet.packet_type != PacketType::Auth.into() {
        bail!(RconError::InvalidPacketType(packet.packet_type))
    }

    let password = packet.body_string()?;

    if password != rcon_password {
        send_rcon(socket, -1, PacketType::AuthResponse, "").await?;
        bail!(RconError::InvalidPassword(password.to_string()))
    }

    send_rcon(socket, packet.packet_id, PacketType::AuthResponse, "").await?;

    Ok(())
}

async fn send_rcon(socket: &mut TcpStream, packet_id: i32, packet_type: PacketType, body: &str) -> Result<()> {
    let body_bytes = body.as_bytes();

    let packet_size = (body_bytes.len() + 10) as i32;

    socket.write_i32_le(packet_size).await?;
    socket.write_i32_le(packet_id).await?;
    socket.write_i32_le(packet_type.into()).await?;

    if !body.is_empty() {
        socket.write(body_bytes).await?;
    }

    socket.write_i8(0).await?;
    socket.write_i8(0).await?;
    socket.flush().await?;

    Ok(())
}

async fn listen_server() -> Result<()> {
    let rcon_password = env::var("RCON_PASSWORD")?;
    let bind_address = env::var("BIND_ADDRESS")?;

    let listener = TcpListener::bind(&bind_address).await?;
    info!("Listening on {}", bind_address);

    loop {
        let (socket, socket_addr) = listener.accept().await?;
        let rcon_password = rcon_password.clone();

        tokio::spawn(async move {
            info!("New connection {}", socket_addr);
            if let Err(err) = accept(&rcon_password, socket, socket_addr).await {
                let error = match err.downcast_ref::<io::Error>() {
                    Some(io_error) => match io_error.kind() == ConnectionAborted || io_error.kind() == BrokenPipe {
                        true => None,
                        false => Some(err)
                    }
                    None => Some(err)
                };

                error.map(|error| error!("Failed to handle connection: {}", error));
            };
            info!("{} disconnected", socket_addr);
        });
    }
}

#[cfg(unix)]
pub async fn listen_signal() -> Result<()> {
    use tokio;
    use tokio::signal::unix::{signal, SignalKind};

    tokio::spawn(async {
        let mut s = signal(SignalKind::hangup())?;
        let hangup = s.recv();
        let mut s = signal(SignalKind::terminate())?;
        let terminate = s.recv();
        let mut s = signal(SignalKind::interrupt())?;
        let interrupt = s.recv();
        let mut s = signal(SignalKind::quit())?;
        let quit = s.recv();

        tokio::select! {
            _ = hangup => {}
            _ = terminate => {}
            _ = interrupt => {}
            _ = quit => {}
        }
        Ok(())
    })
        .await?
}

#[cfg(not(unix))]
pub async fn listen_signal() -> Result<()> {
    let () = std::future::pending().await;
    unreachable!();
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenv();
    env_logger::init();

    select! {
        result = listen_signal() => result?,
        result = listen_server() => result?
    }

    Ok(())
}

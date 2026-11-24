//! hedge — прозрачный локальный туннель, который повторяет неудавшееся TLS-рукопожатие.
//!
//! Проблема, которую решает: TCP-соединение устанавливается, а сервер рвёт TLS на середине
//! рукопожатия (`SSL routines::unexpected eof while reading`). pacman, gh, curl и Gmail API
//! видят «сеть недоступна» и падают, хотя проблема — один потерянный байт в самом начале.
//!
//! Идея: до того как сервер прислал ХОТЬ ОДИН байт, соединение ничего не значит.
//! Клиентский ClientHello — stateless, его можно отправить заново в новое соединение.
//! Прокси запоминает всё, что клиент успел послать, и при обрыве на этапе рукопожатия
//! открывает соединение заново и повторяет байты. Клиент об этом не узнаёт: для него
//! просто «сеть иногда медленнее». После первого байта ответа — чистая перекачка байтов.
//!
//! Режимы:
//!   hedge --listen 127.0.0.1:8899 [--retries 5]  — HTTP CONNECT (pacman/curl/gh)
//!   hedge --socks5 127.0.0.1:7891 [--retries 5]  — SOCKS5 CONNECT + UDP ASSOCIATE
//!                                                  (tun2socks / Android VPN)
//! Оба флага можно задать одновременно.
//!
//! Зависимостей нет: только std + потоки.

use std::env;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

static TUNNELS: AtomicU64 = AtomicU64::new(0);
static REPLAYS: AtomicU64 = AtomicU64::new(0);
static FAILURES: AtomicU64 = AtomicU64::new(0);
static UDP_RELAYS: AtomicU64 = AtomicU64::new(0);

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|arg| arg == name).and_then(|index| args.get(index + 1).cloned())
}

fn dial(host: &str, port: u16, timeout: Duration) -> std::io::Result<TcpStream> {
    let addresses = (host, port).to_socket_addrs()?;
    let mut last_error = std::io::Error::new(ErrorKind::AddrNotAvailable, "no addresses");
    for address in addresses {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(err) => last_error = err,
        }
    }
    Err(last_error)
}

/// Читает заголовок запроса до пустой строки (максимум 8 КБ).
fn read_head(client: &mut TcpStream) -> std::io::Result<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while head.len() < 8192 {
        match client.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(String::from_utf8_lossy(&head).to_string())
}

fn pump(mut from: TcpStream, mut to: TcpStream) {
    let mut buffer = [0u8; 16384];
    loop {
        match from.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                if to.write_all(&buffer[..count]).is_err() {
                    break;
                }
            }
            Err(err) if err.kind() == ErrorKind::Interrupted || err.kind() == ErrorKind::WouldBlock => continue,
            Err(_) => break,
        }
    }
    let _ = to.shutdown(std::net::Shutdown::Write);
}

/// Сердце hedge: клиент уже подключён и приветствие (если положено) отправлено.
/// Пока сервер не ответил первым байтом — буферизуем клиентские байты; при обрыве
/// переоткрываем соединение и повторяем их. После первого байта — чистая перекачка.
fn run_tunnel(mut client: TcpStream, host: String, port: u16, retries: u32) {
    let mut buffered: Vec<u8> = Vec::new(); // всё, что клиент успел отправить — для повтора
    let mut attempt = 0u32;
    let mut reply_sent = false;

    while attempt < retries {
        attempt += 1;
        let mut upstream = match dial(&host, port, Duration::from_secs(6)) {
            Ok(stream) => stream,
            Err(_) => continue,
        };
        // окно рукопожатия: сервер должен ответить в течение 6 с
        let _ = upstream.set_read_timeout(Some(Duration::from_millis(300)));
        let _ = upstream.set_write_timeout(Some(Duration::from_secs(6)));

        if !buffered.is_empty() && upstream.write_all(&buffered).is_err() {
            continue; // соединение умерло ещё до отправки — берём следующее
        }

        if !reply_sent {
            let ok = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").is_ok();
            if !ok {
                return;
            }
            reply_sent = true;
        }

        // --- фаза рукопожатия: ждём первый байт от сервера ---
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut first_server_byte = false;
        let mut scratch = [0u8; 16384];
        let mut broken = false;

        while Instant::now() < deadline && !first_server_byte {
            // клиент → буфер → сервер
            let _ = client.set_read_timeout(Some(Duration::from_millis(20)));
            match client.read(&mut scratch) {
                Ok(0) => return, // клиент закрыл соединение
                Ok(count) => {
                    buffered.extend_from_slice(&scratch[..count]);
                    if upstream.write_all(&scratch[..count]).is_err() {
                        broken = true;
                        break;
                    }
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut => {}
                Err(err) if err.kind() == ErrorKind::Interrupted => {}
                Err(_) => return,
            }

            // сервер → клиент
            match upstream.read(&mut scratch) {
                Ok(0) => {
                    broken = true; // оборвал до ответа — повторяем рукопожатие
                    break;
                }
                Ok(count) => {
                    first_server_byte = true;
                    if client.write_all(&scratch[..count]).is_err() {
                        return;
                    }
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut => {}
                Err(err) if err.kind() == ErrorKind::Interrupted => {}
                Err(_) => {
                    broken = true;
                    break;
                }
            }
        }

        if !broken && first_server_byte {
            // --- рабочая фаза: обычная перекачка байтов ---
            let _ = client.set_read_timeout(None);
            let _ = upstream.set_read_timeout(None);
            let (client_read, client_write) = match (client.try_clone(), client.try_clone()) {
                (Ok(read), Ok(write)) => (read, write),
                _ => return,
            };
            let upstream_for_thread = match upstream.try_clone() {
                Ok(stream) => stream,
                Err(_) => return,
            };
            let tunnel_index = TUNNELS.fetch_add(1, Ordering::Relaxed) + 1;
            if attempt > 1 {
                let replays = REPLAYS.fetch_add(1, Ordering::Relaxed) + 1;
                println!(
                    "tunnel #{tunnel_index} {host}:{port} — handshake retried ({attempt} attempts, {replays} replays total)"
                );
            }
            let _ = std::io::stdout().flush();
            let thread = std::thread::spawn(move || pump(upstream, client_write));
            pump(client_read, upstream_for_thread);
            let _ = thread.join();
            return;
        }

        if Instant::now() >= deadline && !broken {
            // таймаут рукопожатия — тоже повод повторить, если сервер молчал
            broken = true;
        }
        if !broken {
            break;
        }
        // пауза перед повтором, чтобы не долбить сервер в стену
        std::thread::sleep(Duration::from_millis(40 * attempt as u64));
    }

    let failures = FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
    eprintln!("hedge: {host}:{port} — gave up after {retries} attempts ({failures} failures total)");
    let _ = std::io::stderr().flush();
    if !reply_sent {
        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    }
}

/// HTTP CONNECT-режим: pacman/curl/gh присылают «CONNECT host:port HTTP/1.1».
fn handle_http(mut client: TcpStream, retries: u32) {
    let head = match read_head(&mut client) {
        Ok(head) => head,
        Err(_) => return,
    };
    let first_line = head.lines().next().unwrap_or_default().to_string();
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();

    if method != "CONNECT" {
        let body = "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = client.write_all(body.as_bytes());
        return;
    }

    let (host, port) = match target.rsplit_once(':') {
        Some((host, port)) => (host.to_string(), port.parse::<u16>().unwrap_or(443)),
        None => (target.to_string(), 443),
    };

    run_tunnel(client, host, port, retries);
}

fn read_exact(client: &mut TcpStream, n: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    client.read_exact(&mut buf)?;
    Ok(buf)
}

/// Читает цель SOCKS5-запроса: atyp + addr + port (голову ver/cmd/rsv/atyp читает вызывающий).
fn read_socks5_target(client: &mut TcpStream, atyp: u8) -> std::io::Result<(String, u16)> {
    match atyp {
        0x01 => {
            let b = read_exact(client, 6)?;
            let ip = std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            let port = u16::from_be_bytes([b[4], b[5]]);
            Ok((ip.to_string(), port))
        }
        0x04 => {
            let b = read_exact(client, 18)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&b[..16]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([b[16], b[17]]);
            Ok((ip.to_string(), port))
        }
        0x03 => {
            let n = read_exact(client, 1)?[0] as usize;
            if n == 0 {
                return Err(std::io::Error::new(ErrorKind::InvalidData, "empty domain"));
            }
            let b = read_exact(client, n + 2)?;
            let host = String::from_utf8_lossy(&b[..n]).to_string();
            let port = u16::from_be_bytes([b[n], b[n + 1]]);
            Ok((host, port))
        }
        _ => Err(std::io::Error::new(ErrorKind::InvalidData, "unsupported atyp")),
    }
}

fn write_socks5_ipv4_reply(client: &mut TcpStream, reply: u8, addr: [u8; 4], port: u16) {
    let mut r = vec![0x05, reply, 0x00, 0x01];
    r.extend_from_slice(&addr);
    r.extend_from_slice(&port.to_be_bytes());
    let _ = client.write_all(&r);
}

/// Вход SOCKS5: приветствие, запрос, ответ, ветка CONNECT/UDP ASSOCIATE.
fn handle_socks5(mut client: TcpStream, retries: u32) {
    let greeting = match read_exact(&mut client, 2) {
        Ok(g) => g,
        Err(_) => return,
    };
    if greeting[0] != 0x05 || greeting[1] == 0 {
        return;
    }
    let methods = match read_exact(&mut client, greeting[1] as usize) {
        Ok(m) => m,
        Err(_) => return,
    };
    if !methods.contains(&0x00) {
        let _ = client.write_all(&[0x05, 0xFF]);
        return;
    }
    let _ = client.write_all(&[0x05, 0x00]); // no-auth

    let head = match read_exact(&mut client, 4) {
        Ok(h) => h,
        Err(_) => return,
    };
    if head[0] != 0x05 {
        return;
    }
    let cmd = head[1];
    let (host, port) = match read_socks5_target(&mut client, head[3]) {
        Ok(t) => t,
        Err(_) => {
            write_socks5_ipv4_reply(&mut client, 0x08, [0, 0, 0, 0], 0);
            return;
        }
    };

    match cmd {
        0x01 => {
            // CONNECT: успех отправляем сразу — клиент начинает слать ClientHello,
            // который буферизуется и при обрыве повторяется. Это и есть суть hedge.
            write_socks5_ipv4_reply(&mut client, 0x00, [0, 0, 0, 0], 0);
            run_tunnel(client, host, port, retries);
        }
        0x03 => {
            socks5_udp_relay(client);
        }
        _ => {
            write_socks5_ipv4_reply(&mut client, 0x07, [0, 0, 0, 0], 0);
        }
    }
}

/// Цель внутри UDP-датаграммы: [rsv, frag, atyp, addr…, port, payload] → (host, port, длина заголовка)
fn parse_datagram_target(buf: &[u8]) -> Option<(String, u16, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let atyp = buf[3];
    match atyp {
        0x01 => {
            if buf.len() < 10 {
                return None;
            }
            let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            Some((ip.to_string(), port, 10))
        }
        0x03 => {
            let n = buf[4] as usize;
            if buf.len() < 5 + n + 2 {
                return None;
            }
            let host = String::from_utf8_lossy(&buf[5..5 + n]).to_string();
            let port = u16::from_be_bytes([buf[5 + n], buf[6 + n]]);
            Some((host, port, 7 + n))
        }
        0x04 => {
            if buf.len() < 22 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[4..20]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            Some((ip.to_string(), port, 22))
        }
        _ => None,
    }
}

/// UDP ASSOCIATE: релей дейтаграмм клиент ⇄ цель (DNS и прочий UDP).
/// Реплей здесь неприменим (датаграммы stateless) — чистая пересылка.
fn socks5_udp_relay(mut client: TcpStream) {
    let udp = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => {
            write_socks5_ipv4_reply(&mut client, 0x01, [0, 0, 0, 0], 0);
            return;
        }
    };
    let bnd_port = match udp.local_addr() {
        Ok(a) => a.port(),
        Err(_) => {
            write_socks5_ipv4_reply(&mut client, 0x01, [0, 0, 0, 0], 0);
            return;
        }
    };
    // tun2socks живёт на том же устройстве → BND.ADDR 127.0.0.1
    write_socks5_ipv4_reply(&mut client, 0x00, [127, 0, 0, 1], bnd_port);
    UDP_RELAYS.fetch_add(1, Ordering::Relaxed);

    let _ = udp.set_read_timeout(Some(Duration::from_millis(100)));

    // TCP-сессия ASSOCIATE закрыта клиентом → релей завершается
    let stopped = Arc::new(AtomicBool::new(false));
    {
        let stopped = Arc::clone(&stopped);
        std::thread::spawn(move || {
            let mut byte = [0u8; 1];
            loop {
                match client.read(&mut byte) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            stopped.store(true, Ordering::Relaxed);
        });
    }

    // адрес клиента-отправителя датаграмм: фиксируется первым пакетом
    let mut peer: Option<std::net::SocketAddr> = None;
    let mut buf = [0u8; 65536];
    loop {
        if stopped.load(Ordering::Relaxed) {
            break;
        }
        match udp.recv_from(&mut buf) {
            Ok((count, from)) => {
                let is_client = match peer {
                    Some(p) => p == from,
                    None => true, // первый пакет — от клиента
                };
                if is_client {
                    if count < 4 || buf[2] != 0x00 {
                        continue; // фрагментация не поддерживается
                    }
                    let (host, port, hlen) = match parse_datagram_target(&buf[..count]) {
                        Some(t) => t,
                        None => continue,
                    };
                    if peer.is_none() {
                        peer = Some(from);
                    }
                    let targets = match (host.as_str(), port).to_socket_addrs() {
                        Ok(a) => a,
                        Err(_) => continue,
                    };
                    if let Some(target) = targets.into_iter().next() {
                        let _ = udp.send_to(&buf[hlen..count], target);
                    }
                } else {
                    // цель → клиент: оборачиваем в SOCKS5-заголовок
                    if let Some(p) = peer {
                        let mut out = vec![0x00, 0x00, 0x00];
                        match from {
                            std::net::SocketAddr::V4(v4) => {
                                out.push(0x01);
                                out.extend_from_slice(&v4.ip().octets());
                            }
                            std::net::SocketAddr::V6(v6) => {
                                out.push(0x04);
                                out.extend_from_slice(&v6.ip().octets());
                            }
                        }
                        out.extend_from_slice(&(count as u16).to_be_bytes());
                        out.extend_from_slice(&buf[..count]);
                        let _ = udp.send_to(&out, p);
                    }
                }
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut || err.kind() == ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
}

fn serve_socks5(listener: TcpListener, retries: u32) {
    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            let _ = stream.set_nodelay(true);
            std::thread::spawn(move || handle_socks5(stream, retries));
        }
    }
}

fn serve_http(listener: TcpListener, retries: u32) {
    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            let _ = stream.set_nodelay(true);
            std::thread::spawn(move || handle_http(stream, retries));
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let retries: u32 = arg_value(&args, "--retries").and_then(|v| v.parse().ok()).unwrap_or(6);
    let http_listen = arg_value(&args, "--listen");
    let socks5_listen = arg_value(&args, "--socks5");
    if http_listen.is_none() && socks5_listen.is_none() {
        eprintln!("hedge: укажите --listen <addr> (HTTP CONNECT) и/или --socks5 <addr> (SOCKS5)");
        eprintln!("пример: hedge --socks5 127.0.0.1:7891 --retries 6");
        std::process::exit(1);
    }

    let mut threads = Vec::new();
    if let Some(listen) = http_listen {
        match TcpListener::bind(&listen) {
            Ok(listener) => {
                println!("hedge listening on http://{listen} (retries per tunnel: {retries})");
                println!("check: https_proxy=http://{listen} curl -sS https://api.github.com");
                threads.push(std::thread::spawn(move || serve_http(listener, retries)));
            }
            Err(err) => {
                eprintln!("hedge: cannot bind {listen}: {err}");
                std::process::exit(1);
            }
        }
    }
    if let Some(listen) = socks5_listen {
        match TcpListener::bind(&listen) {
            Ok(listener) => {
                println!("hedge listening on socks5://{listen} (retries per tunnel: {retries}, UDP: on)");
                println!("check: curl -sS --socks5-hostname {listen} https://api.github.com");
                threads.push(std::thread::spawn(move || serve_socks5(listener, retries)));
            }
            Err(err) => {
                eprintln!("hedge: cannot bind {listen}: {err}");
                std::process::exit(1);
            }
        }
    }
    let _ = std::io::stdout().flush();
    for thread in threads {
        let _ = thread.join();
    }
}

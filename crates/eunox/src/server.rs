//! The report over HTTP: `/` (HTML), `/report.txt`, `/metrics`, `/healthz`.

use std::convert::Infallible;
use std::io;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, header};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::app::App;
use crate::render;

/// Serve forever.
pub async fn serve(listener: TcpListener, app: Arc<App>) -> io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let app = app.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let app = app.clone();
                async move { Ok::<_, Infallible>(handle(&app, &req)) }
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

fn handle(app: &App, req: &Request<Incoming>) -> Response<Full<Bytes>> {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return reply(
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain; charset=utf-8",
            "GET only\n".into(),
        );
    }
    match req.uri().path() {
        "/" => reply(
            StatusCode::OK,
            "text/html; charset=utf-8",
            app.render(render::html),
        ),
        "/report.txt" => reply(
            StatusCode::OK,
            "text/plain; charset=utf-8",
            app.render(render::text),
        ),
        "/metrics" => reply(
            StatusCode::OK,
            "text/plain; version=0.0.4; charset=utf-8",
            app.render(render::metrics),
        ),
        "/healthz" => reply(StatusCode::OK, "text/plain; charset=utf-8", "ok\n".into()),
        _ => reply(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            "not found\n".into(),
        ),
    }
}

fn reply(status: StatusCode, content_type: &str, body: String) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from(body)));
    *resp.status_mut() = status;
    let headers = resp.headers_mut();
    if let Ok(v) = content_type.parse() {
        headers.insert(header::CONTENT_TYPE, v);
    }
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'"),
    );
    resp
}

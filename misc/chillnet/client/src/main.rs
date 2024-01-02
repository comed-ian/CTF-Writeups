use reqwest;
use std::{thread, time};

async fn get_uid(endpoint: &str) -> Result<String, reqwest::Error> {
    let mut url = "https://c2.chillmilk.org/".to_string();
    url.push_str(endpoint);
    let text = reqwest::get(url)
        .await?
        .text()
        .await?;

    Ok(text)
}

async fn send_beat(uid: &String) -> Result<String, reqwest::Error> {
    let mut url = "https://c2.chillmilk.org/beat/".to_string();
    url.push_str(uid);
    let text = reqwest::get(url)
        .await?
        .text()
        .await?;

    Ok(text)
}

#[tokio::main]
async fn main() {
    let uid = get_uid("uid").await.expect("Failed to get UUID");
    println!("got uid = {uid}");
    let mut ms = 160;
    loop {
        let resp = send_beat(&uid).await.expect("Failed to send beat");
        println!("{resp}");
        if resp.contains("CS{") { break; }
        if resp.starts_with("You are too slow!") { ms -= 1; }
        else if resp.starts_with("You are too fast!") { ms += 1; }

        let sleep_time = time::Duration::from_millis(ms);
        thread::sleep(sleep_time);
    }
}

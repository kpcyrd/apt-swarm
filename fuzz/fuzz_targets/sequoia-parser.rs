#![no_main]

use apt_swarm::errors::*;
use apt_swarm::sequoia_openpgp::parse::{PacketParser, PacketParserResult, Parse};
use libfuzzer_sys::fuzz_target;

fn parse(data: &[u8]) -> Result<()> {
    let mut ppr = PacketParser::from_bytes(data)?;
    while let PacketParserResult::Some(pp) = ppr {
        let (_packet, next_ppr) = pp.recurse()?;
        ppr = next_ppr;
    }
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    parse(data).ok();
});

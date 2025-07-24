use bitcoin::block::Header as BlockHeader;

impl BtcHeaderInfo {
    pub fn block_header(&self) -> Result<BlockHeader, bitcoin::consensus::encode::Error> {
        bitcoin::consensus::deserialize(self.header.as_ref())
    }
}

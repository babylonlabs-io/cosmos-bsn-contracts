pub mod babylon {
    // Skip for the auto-generated code.
    #![allow(clippy::doc_lazy_continuation)]

    pub mod btccheckpoint {
        // @@protoc_insertion_point(attribute:babylon.btccheckpoint.v1)
        pub mod v1 {
            #![allow(clippy::uninlined_format_args)]
            #![allow(clippy::large_enum_variant)]
            include!("gen/babylon.btccheckpoint.v1.rs");
            // @@protoc_insertion_point(babylon.btccheckpoint.v1)
        }
    }
    pub mod btclightclient {
        // @@protoc_insertion_point(attribute:babylon.btclightclient.v1)
        pub mod v1 {
            #![allow(clippy::uninlined_format_args)]
            #![allow(clippy::large_enum_variant)]
            include!("gen/babylon.btclightclient.v1.rs");
            // @@protoc_insertion_point(babylon.btclightclient.v1)
        }
    }
    pub mod checkpointing {
        // @@protoc_insertion_point(attribute:babylon.checkpointing.v1)
        pub mod v1 {
            #![allow(clippy::uninlined_format_args)]
            #![allow(clippy::large_enum_variant)]
            include!("gen/babylon.checkpointing.v1.rs");
            // @@protoc_insertion_point(babylon.checkpointing.v1)
            include!("impl/babylon.checkpointing.v1.impl.rs");
        }
    }
    pub mod epoching {
        // @@protoc_insertion_point(attribute:babylon.epoching.v1)
        pub mod v1 {
            #![allow(clippy::uninlined_format_args)]
            #![allow(clippy::large_enum_variant)]
            include!("gen/babylon.epoching.v1.rs");
            // @@protoc_insertion_point(babylon.epoching.v1)
        }
    }
    pub mod zoneconcierge {
        // @@protoc_insertion_point(attribute:babylon.zoneconcierge.v1)
        pub mod v1 {
            #![allow(clippy::uninlined_format_args)]
            #![allow(clippy::large_enum_variant)]
            include!("gen/babylon.zoneconcierge.v1.rs");
            // @@protoc_insertion_point(babylon.zoneconcierge.v1)
        }
    }
    pub mod btcstaking {
        // @@protoc_insertion_point(attribute:babylon.btcstaking.v1)
        pub mod v1 {
            #![allow(clippy::uninlined_format_args)]
            #![allow(clippy::large_enum_variant)]
            include!("gen/babylon.btcstaking.v1.rs");
            // @@protoc_insertion_point(babylon.btcstaking.v1)
        }
    }
    pub mod finality {
        // @@protoc_insertion_point(attribute:babylon.finality.v1)
        pub mod v1 {
            #![allow(clippy::uninlined_format_args)]
            #![allow(clippy::large_enum_variant)]
            include!("gen/babylon.finality.v1.rs");
            // @@protoc_insertion_point(babylon.finality.v1)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::babylon::checkpointing::v1::RawCheckpoint;
    use prost::Message;
    use std::fs;

    #[test]
    fn test_deserialize_protobuf_bytes_from_go() {
        let testdata_file = "../test-utils/testdata/raw_ckpt.dat";
        let testdata: &[u8] = &fs::read(testdata_file).unwrap();
        let raw_ckpt = RawCheckpoint::decode(testdata).unwrap();
        assert!(raw_ckpt.epoch_num == 12345);
    }
}

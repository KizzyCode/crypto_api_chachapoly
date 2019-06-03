extern crate rand;
extern crate sodiumoxide;

use crypto_api_chachapoly::{ ChachaPolyIetf };
use crypto_api::{ cipher::AeadCipher };
use rand::Rng;
use sodiumoxide::crypto::aead::chacha20poly1305_ietf;

fn main() {
    let chachapoly = ChachaPolyIetf { };

    let mut rng = rand::thread_rng();
    let mut test_count : u64 = 0;
    loop {
        let key = chacha20poly1305_ietf::gen_key();
        let nonce = chacha20poly1305_ietf::gen_nonce();

        let mut pt = vec![0u8; rng.gen_range(0, 65)];
        rng.fill(pt.as_mut_slice());

        let ad = {
            if rng.gen_bool(0.5) {
                pt.clone()
            } else {
                vec![0u8; 0]
            }
        };

        let mut ct_ours = vec![0u8; pt.len() + 16];

        chachapoly.seal_to(&mut ct_ours, &pt, &ad, key.as_ref(), nonce.as_ref()).unwrap();

        let ct_sodium = chacha20poly1305_ietf::seal(
            &pt,
            if ad.len() > 0 { Some(&ad) } else { None },
            &nonce,
            &key
        );

        if ct_ours != ct_sodium {
            println!("FAILURE! This library and libsodium don't match. Inputs:");
            println!("Key: {:?}", key.as_ref());
            println!("Nonce: {:?}", nonce.as_ref());
            println!("Plaintext: {:?}", pt);
            println!("Additional data: {:?}", ad);
            println!("Outputs:");
            println!("Ours: {:?}", ct_ours);
            println!("Libsodium: {:?}", ct_sodium);
            break;
        }

        test_count += 1;
        let scale = 1000000;
        if test_count % scale == 0 {
            println!("Completed {}M tests.", test_count/scale);
        }
    }

}

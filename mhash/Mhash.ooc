use mhash
include mhash

mhash_init: extern func (type: Algo) -> InstanceStruct*
mhash: extern func (is: InstanceStruct*, plaintext: String, size: Long) -> Bool
mhash_get_block_size: extern func (type: Algo) -> Long
mhash_end: extern func (is: InstanceStruct*) -> Pointer

InstanceStruct: cover from MHASH* {
	hmac_key_size: extern Long
	hmac_block: extern Long
	hmac_key: extern Char

	state: extern Char
	state_size: extern Long
	algorithm_given: extern Int

	HASH_FUNC: extern Func
	FINAL_FUNC: extern Func
	DEINIT_FUNC: extern Func
}

Mhash: class {
    /** Represents a session with MHash. Data can be added, but not deleted */

    is: InstanceStruct*
    algo: Algo

    init: func(a: Algo) {
        this is = mhash_init(a)
        this algo = a
    }

    feed: func(plaintext: String) {
        /** Feeds (adds) string data to the session */
        mhash(this is, plaintext, plaintext length())
    }

    rawdigest: func() -> UChar* {
        /** Returns the message digest as unsigned chars */
        return mhash_end(this is) as UChar*
    }

    hexdigest: func() -> String {
        /** Returns the message digest as a string of hexadecimal characters */
        hash := this rawdigest()
        blocksize := mhash_get_block_size(this algo)
        i := 0
        ret := ""
        
        while (i < blocksize) {
            ret += "%.2x" format(hash[i])
            i += 1
        }        

        return ret
    }
}

Algo: enum {
    CRC32 =  0
    MD5 =  1
    SHA1 =  2
    HAVAL256 =  3
    RIPEMD160 =  5
    TIGER192 =  7
    GOST =  8
    CRC32B =  9
    HAVAL224 = 10
    HAVAL192 = 11
    HAVAL160 = 12
    HAVAL128 = 13
    TIGER128 = 14
    TIGER160 = 15
    MD4 = 16
    SHA256 = 17
    ADLER32 = 18
    SHA224 = 19
    SHA512 = 20
    SHA384 = 21
    WHIRLPOOL = 22
    RIPEMD128 = 23
    RIPEMD256 = 24
    RIPEMD320 = 25
    SNEFRU128 = 26
    SNEFRU256 = 27
    MD2 = 28
}

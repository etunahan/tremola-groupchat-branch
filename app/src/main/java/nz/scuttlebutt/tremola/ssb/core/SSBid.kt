package nz.scuttlebutt.tremola.ssb.core

import java.security.SecureRandom
import android.util.Base64
import android.util.Log
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import com.goterl.lazysodium.interfaces.Sign
import com.goterl.lazysodium.utils.KeyPair
import org.json.JSONObject

import nz.scuttlebutt.tremola.ssb.core.Crypto.Companion.signDetached
import nz.scuttlebutt.tremola.utils.HelperFunctions.Companion.toBase64
import nz.scuttlebutt.tremola.utils.Json_PP
import kotlin.experimental.xor
import kotlin.math.ceil

class SSBid { // ed25519

    constructor(secret: ByteArray, public: ByteArray) {
        signingKey = secret
        verifyKey = public
    }

    constructor(key: ByteArray) {
        if (key.size == Sign.ED25519_PUBLICKEYBYTES) {
            signingKey = null
            verifyKey = key
        } else { // secret key
            signingKey = key
            verifyKey = ByteArray(Sign.ED25519_PUBLICKEYBYTES)
            lazySodiumInst.cryptoSignEd25519SkToPk(verifyKey, signingKey)
        }
    }

    constructor(str: String) {
        val s = str.slice(1..str.lastIndex).removeSuffix(".ed25519")
        verifyKey = Base64.decode(s, Base64.NO_WRAP)
    }

    constructor(k: KeyPair) {
        signingKey = k.secretKey.asBytes
        verifyKey = k.publicKey.asBytes
    }
    constructor() { // generate new ID
        val keypair = lazySodiumInst.cryptoSignKeypair()
        signingKey = keypair.secretKey.asBytes
        verifyKey = keypair.publicKey.asBytes
    }

    var signingKey:   ByteArray? = null // private
    var verifyKey:    ByteArray         // public i.e., the SSB ID proper
    private val lazySodiumInst = Crypto.lazySodiumInst

    // ------------------------------------------------------------------------

    fun toRef(): String {
        return "@" + verifyKey.toBase64() + ".ed25519"
    }

    fun toExportString(): String? {
        if (signingKey == null) return null
        val s = Base64.encode(signingKey, Base64.NO_WRAP).decodeToString()
        return "{\"curve\":\"ed25519\",\"secret\":\"${s}\"}"
    }

    fun sign(data: ByteArray): ByteArray {
        val signature = ByteArray(Sign.BYTES)
        if (lazySodiumInst.cryptoSignDetached(signature, data, data.size.toLong(), signingKey!!))
            return signature
        throw Exception("Could not sign with Identity.")
    }

    fun verify(signature: ByteArray, data: ByteArray): Boolean {
        return lazySodiumInst.cryptoSignVerifyDetached(signature, data, data.size, verifyKey)
    }

    private fun ed25519PktoCurve(pk: ByteArray): ByteArray {
        val c = ByteArray(Sign.CURVE25519_PUBLICKEYBYTES)
        lazySodiumInst.convertPublicKeyEd25519ToCurve25519(c, pk)
        return c
    }

    private fun ed25519SktoCurve(sk: ByteArray): ByteArray {
        val c = ByteArray(Sign.CURVE25519_SECRETKEYBYTES)
        lazySodiumInst.convertSecretKeyEd25519ToCurve25519(c, sk)
        return c
    }

    fun deriveSharedSecretAb(publicKey: ByteArray): ByteArray {
        val curve_sk = ed25519SktoCurve(signingKey!!)
        val shared = ByteArray(32)
        lazySodiumInst.cryptoScalarMult(shared, curve_sk, publicKey)
        return shared
    }

    private fun twoBytesToInt(buffer: ByteArray): Int {

        return (buffer[1].toInt() and 0xff shl 8) or
                (buffer[0].toInt() and 0xff)
    }

    fun intToTwoBytes(buffer: ByteArray, number: Int){

        for (i in buffer.indices)
            buffer[i * 1] = (number shr (i * 8)).toByte()

    }

    fun encodeUInt16(length: Int): ByteArray {

        var out = ByteArray(2)
        out[0] = (length and 0xFF).toByte()
        out[1] = (length shr 8).toByte()

        return out
    }

    // Shallow Length-prefixed encoding (SLP)
    fun slpEncode(info: Array<ByteArray>): ByteArray {

        var encodedInfo = ByteArray(0)
        for (elem in info){

            encodedInfo = encodedInfo.plus(encodeUInt16(elem.size)).plus(elem)

        }

        return encodedInfo
    }


    //Creates a Hasher (HmacSHA256) and hashes the data with this Hasher
    fun createHmacSha256(key: ByteArray, data: ByteArray): ByteArray {

        // make an HMAC hasher
        val mac = Mac.getInstance("HmacSHA256") // or hmacSHA256

        // to initialize we need a HMAC key
        val secretKey = SecretKeySpec(key, "HmacSHA256")

        // initialize the HMAC hasher with the secret (HMAC) key
        mac.init(secretKey)

        return mac.doFinal(data)
    }

    fun hkdf_expand(key: ByteArray, info: ByteArray, length: Int): ByteArray {

        // (see https://github.com/futoin/util-js-hkdf)

        val hashLen = 32
        var t = ByteArray(0)
        var okm = ByteArray(0) //output key material
        val range = ceil((length/hashLen).toDouble()).toInt()
        var bytes = arrayOf<Byte>(0x01, 0x02, 0x03, 0x04, 0x05) //range is always < 6
        for (i in 0..range){
            val data = t.plus(info).plus(bytes[i])
            okm += createHmacSha256(key, data)
            t = t.plus(data)
        }

        return okm.sliceArray(0 until length)
    }


    fun deriveSecret(key: ByteArray, feed_id: ByteArray, prev_msg_id: ByteArray, labels: Array<String>, length: Int): ByteArray {
        // (see https://github.com/ssbc/envelope-spec/blob/master/derive_secret/README.md)
        // var info = ['envelope', feed_id, prev_msg_id].concat(labels) //.concat => .plus()

        // make an array and add the labels like in the given specification
        // (the Strings in the array need to be encoded in utf-8 DIFFERENT as the rest (BASE64))
        var info = arrayOf("envelope".toByteArray(Charsets.UTF_8), feed_id, prev_msg_id)
        for (string in labels) {
            info = info.plus(string.toByteArray(Charsets.UTF_8))
        }

        //encode it -> encode(info). need to be bytearray.
        val encodedInfo = slpEncode(info)

        return hkdf_expand(key, encodedInfo, length)
    }

    fun slot(msg_key: ByteArray, feed_id: ByteArray, prev_msg_id: ByteArray, rec_key: ByteArray, scheme: String="envelope-large-symmetric-group"): ByteArray {

        // derive a key_slot for a specific recipient

        val key_slot = ByteArray(32)
        val derivedSecret = deriveSecret(rec_key, feed_id, prev_msg_id, arrayOf("slot_key", scheme), 32)

        //XOR of msg_key & derivedSecret (to get the slot_content)
        for(index in key_slot.indices){
            key_slot[index] = msg_key[index].xor(derivedSecret[index])
        }

        return key_slot
    }

    fun unslot(key_slot: ByteArray, feed_id: ByteArray, prev_msg_id: ByteArray, rec_key: ByteArray, scheme: String="envelope-large-symmetric-group"): ByteArray {

        // to get the msg_key from a slot, we need to make the opposite of what we've done in slot()

        val derivedSecret = deriveSecret(rec_key, feed_id, prev_msg_id, arrayOf("slot_key", scheme), 32)
        var msg_key = ByteArray(derivedSecret.size)

        //XOR of slot_content & derivedSecret (to get the message key)
        for(index in msg_key.indices){
            msg_key[index] = key_slot[index].xor(derivedSecret[index])
        }

        return msg_key
    }

    fun encryptPrivateMessage(message: String, recps: List<ByteArray>): String {
        val txt = message.encodeToByteArray()
        val nonce = SecureRandom().generateSeed(24)
        val cdek = SecureRandom().generateSeed(33) // count plus data encryption key
        cdek[0] = recps.size.toByte()
        val dek = cdek.sliceArray(1..32)
        val aKeyPair = lazySodiumInst.cryptoSignKeypair()
        val secret = ed25519SktoCurve(aKeyPair.secretKey.asBytes)
        val public = ed25519PktoCurve(aKeyPair.publicKey.asBytes)
        var boxes = ByteArray(0)
        val kek = ByteArray(32)
        for (k in recps) {
            val sbox = ByteArray(cdek.size + 16)
            lazySodiumInst.cryptoScalarMult(kek, secret, ed25519PktoCurve(k))
            lazySodiumInst.cryptoSecretBoxEasy(sbox, cdek, cdek.size.toLong(), nonce, kek)
            boxes += sbox
        }
        val lastbox = ByteArray(txt.size + 16)
        lazySodiumInst.cryptoSecretBoxEasy(lastbox, txt, txt.size.toLong(), nonce, dek)
        val total = nonce + public + boxes + lastbox
        return Base64.encodeToString(total, Base64.NO_WRAP) + ".box"
    }

    fun encryptGroupMessage(message: String, feed_id: ByteArray, prev_msg_id: ByteArray, rcps: Array<Array<String>>, msg_key: ByteArray=SecureRandom().generateSeed(32), group_id: ByteArray=ByteArray(32)): String? {

        //group_id not needed yet so for that we have a default parameter

        if (message.isEmpty()){
            return null

        }
        val txt = Base64.decode(message, 0)
        // kek = key encryption key
        val read_key = deriveSecret(msg_key, feed_id, prev_msg_id, arrayOf("read_key"), 32)

        //header_box: HMAC (16bit) + header*(16bit: offset(2) + flag(1) + header_ext(13))
        val offset = ByteArray(2) // offset needs to be 2 bytes
        intToTwoBytes(offset, (rcps.size + 1) * 32) // header_box(32bytes) + rcps.size * key_slots(32bytes)
        val flags = ByteArray(1) //ignored
        val header_extensions = ByteArray(13) //ignored
        val header_txt = offset.plus(flags).plus(header_extensions) // same as: offset + flags + header_extensions
        var nonce = ByteArray(24)
        val header_key = deriveSecret(read_key, feed_id, prev_msg_id, arrayOf("header_key"), 32) // derived from read_key
        val header_star = ByteArray(32)
        lazySodiumInst.cryptoSecretBoxEasy(header_star, header_txt, header_txt.size.toLong(), nonce, header_key)

        //key_slots
        var key_slots = ByteArray(0)
        for (recipient in rcps){
            val slot_content = slot(msg_key, feed_id, prev_msg_id, Base64.decode(recipient[0],0), recipient[1])
            key_slots = key_slots.plus(slot_content)
        }

        //body_box
        val body_key = deriveSecret(read_key, feed_id, prev_msg_id, arrayOf("body_key"), 32) //derived from read_key
        val body_star = ByteArray(txt.size + 16)
        lazySodiumInst.cryptoSecretBoxEasy(body_star, txt, txt.size.toLong(), nonce, body_key)

        val total = header_star.plus(key_slots).plus(body_star)

        return Base64.encodeToString(total, 0) + ".box2"
    }

    fun decryptPrivateMessage(message: String): ByteArray? {
        val raw = Base64.decode(message.removeSuffix(".box"), Base64.NO_WRAP)
        val nonce = raw.sliceArray(0..23)
        val pubkey = raw.sliceArray(24..55)
        val kek = ByteArray(32)
        lazySodiumInst.cryptoScalarMult(kek, ed25519SktoCurve(signingKey!!), pubkey)
        var recipients = raw.sliceArray(56 .. raw.lastIndex)

        for (i in 0..6) {
            if (recipients.size < 49) return null
            val cdek = Crypto.secretUnbox(recipients.copyOfRange(0, 49), nonce, kek)
            if (cdek != null) {
                val numberRecipients = cdek[0].toInt()
                val data = raw.sliceArray(56 + numberRecipients*49 .. raw.lastIndex)
                return Crypto.secretUnbox(data, nonce, cdek.sliceArray(1..32))
            }
            recipients = raw.sliceArray(56 + (i+1) * 49 .. raw.lastIndex)
        }
        return null
    }

    fun decryptGroupMessage(message: String, feed_id: ByteArray, prev_msg_id: ByteArray, recp_key: ByteArray, scheme: String): ByteArray? { // group_key, feed_id & prev_msg_id als schnittstelle gegeben vorübergehend

        val raw = Base64.decode(message.removeSuffix(".box2"), 0)

        //header is 32 bits so skip the first 32 bits & start with the first key-slot (at index 32)
        var i = 1
        while ((i < 16) and ((i * 32) < raw.size)){ //we stop after 16 slots (or if we are done)

            var slot_content = raw.copyOfRange(i * 32, (i + 1) * 32)
            val msg_key = unslot(slot_content, feed_id, prev_msg_id, recp_key, scheme)

            // deriving the different keys from the msg_key
            val read_key = deriveSecret(msg_key, feed_id, prev_msg_id, arrayOf("read_key"), 32)
            val header_key = deriveSecret(read_key, feed_id, prev_msg_id, arrayOf("header_key"), 32)

            val header_content = ByteArray(16)
            val succ = lazySodiumInst.cryptoSecretBoxOpenEasy(header_content, raw.copyOfRange(0, 32), 32, ByteArray(24), header_key)

            if (succ){

                // if the unboxing of the header was successful we can read the offset...
                val offset = header_content.copyOfRange(0, 2)
                val offsetInt = twoBytesToInt(offset)

                // ...to get directly to the body_box and also unbox it after deriving the body_key
                val body_key = deriveSecret(read_key, feed_id, prev_msg_id, arrayOf("body_key"), 32)
                val body_content = ByteArray(raw.size - offsetInt - 16)
                lazySodiumInst.cryptoSecretBoxOpenEasy(body_content, raw.copyOfRange(offsetInt, raw.lastIndex + 1), (raw.size - offsetInt).toLong(), ByteArray(24), body_key)

                return body_content
            }
            i += 1
        }

        Log.d("Test ubox", "Wrong place. Message was not for us.")
        return null
    }

    fun getCloakedMsgID(msg_id: ByteArray, read_key: ByteArray): ByteArray{

        val info = arrayOf("cloaked_msg_id".toByteArray(Charsets.UTF_8), msg_id)

        return hkdf_expand(read_key, slpEncode(info), 32)
    }

    fun formatEvent(prev: String?, seq: Int, auth: String, ts: String,
                            hash: String, cont: Any, sig: ByteArray?): String {
         // returns SSB-compliant JSON string, cont is either JSONObject/dict or a string
         var cstr = if (cont is String) "\"${cont}\"" else ((cont as JSONObject)).toString(2)
         cstr = cstr.replace("\n", "\n  ")
         cstr = cstr.replace("\\/", "/") // argh, silly json.org formatting
         var estr = if (prev == null) "{\n  \"previous\": null," else
                                     "{\n  \"previous\": \"${prev}\","
         estr += """
  "sequence": ${seq},
  "author": "${auth}",
  "timestamp": ${ts},
  "hash": "${hash}",
  "content": ${cstr}"""
         if (sig != null)
            estr += ",\n  \"signature\": \"{sig}\"\n}"
         else
            estr += "\n}"
         return Json_PP().makePretty(estr)
    }

    fun signSSBEvent(prev: String?, seq: Int, content: Any): String {
        val estr = formatEvent(prev, seq, this.toRef(), System.currentTimeMillis().toString(),
                         "sha256", content, null)
        val sig = Base64.encode(signDetached(estr.encodeToByteArray(), signingKey!!), Base64.NO_WRAP)
        return ( estr.slice(0..(estr.lastIndex-2)) +
                             ",\n  \"signature\": \"${sig.decodeToString()}.sig.ed25519\"\n}" )
    }
}

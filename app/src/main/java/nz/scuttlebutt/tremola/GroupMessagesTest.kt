package nz.scuttlebutt.tremola

import android.util.Base64
import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.goterl.lazysodium.interfaces.Base
import nz.scuttlebutt.tremola.ssb.TremolaState
import nz.scuttlebutt.tremola.ssb.core.SSBid

import org.junit.Test
import org.junit.runner.RunWith

import org.junit.Assert.*
import java.security.SecureRandom

/**
 * Instrumented test, which will execute on an Android device.
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */

/**
fun main(){
    val myClass = GroupMessagesTest()
    myClass.encryptDecrypt()
}*/


class GroupMessagesTest(val identity: SSBid) {


    fun encryptDecryptTest() {

        val plain_text = "c3F1ZWFtaXNoIG9zc2lmcmFnZSDwn5io"
        val feed_id = Base64.decode("AAAew3905XdfryUoCZkgP4rowDkrzzyxBPDH/ZtIDMzUzw==", 0)
        val prev_msg_id = Base64.decode("AQANw92HovBPgaGzVh6+9M9KvwZXoLYm5c4n0OOtiOP5/w==", 0)
        val group_id = ByteArray(32) //no need since we have given a default zero-ByteArray

        val recipient1 = arrayOf("TMeIncVj/YECjSSthZjfD7OFWonqYR2nPXKacfbE3ck=", "envelope-large-symmetric-group")

        val rcps = arrayOf(recipient1)

        Log.d("Test encryptDecrypt","####################")

        Log.d("Test ed input", plain_text)

        //Log.d("Test","Encrypting...")
        val encrypted = identity.encryptGroupMessage(plain_text, feed_id, prev_msg_id, rcps)
        //Log.d("Test","Encrypted.")

        //Log.d("Test","Decrypting...")
        val output = identity.decryptGroupMessage(encrypted!!, feed_id, prev_msg_id, Base64.decode(recipient1[0],0), recipient1[1])
        //Log.d("Test","Decrypted.")

        Log.d("Test ed output", Base64.encodeToString(output!!, 0))
    }


    fun deriveSecretTest(){

        val feed_id = Base64.decode("AABvA0ViRe2fgDbnrUW6KPDkTwKOMF/NAqqaUlylfnXKLg==", 0)
        val prev_msg_id = Base64.decode("AQDUUCgN3XkHRHRkrATQLORvr4CCrD6VTLGDbTRfMHQZvA==", 0)
        val msg_key = Base64.decode("2PCqq5Lr9rgJffTRsXNqEbNVgLWzTNKOklT8J3y5Diw=", 0)

        Log.d("Test deriveSecret", "####################")

        val read_key = identity.deriveSecret(msg_key, feed_id, prev_msg_id, arrayOf("read_key"), 32)
        Log.d("Test ds read_key", Base64.encodeToString(read_key, 0))
        Log.d("Test ds read_key has to be", "LILUCCUYL0WFAdBmNPzGFS+lFjOoWP+RUSqQ+4j0Y4s=")

        val header_key = identity.deriveSecret(read_key, feed_id, prev_msg_id, arrayOf("header_key"), 32)
        Log.d("Test ds header_key", Base64.encodeToString(header_key, 0))
        Log.d("Test ds header_key has to be", "BbT8RInae0A1KFSwwz6J/muhHkFV/pf9TgKS7jh9S5I=")

        val body_key = identity.deriveSecret(read_key, feed_id, prev_msg_id, arrayOf("body_key"), 32)
        Log.d("Test ds body_key", Base64.encodeToString(body_key, 0))
        Log.d("Test ds body_key has to be", "yY23I1Or1IWg0yCa9I1RG0kk8kyN1+9j3o8nAymkj9E=")
    }

    fun slotTest(){

        val feed_id = Base64.decode("AAAHLRsWrLESb6mIKbRHcdm852/0qNYq2BFFcjWRfQ0OEw==",0)
        val prev_msg_id = Base64.decode("AQBwTpLagCT9AA1nI/WhxSTmYDqmNpx/WF/r+2t8gZxBbA==", 0)
        val msg_key = Base64.decode("zp/EpTlUqzLlSnrXMiAllEUlwxgfnZVv9TeoKDWXM+0=", 0)

        //recipient[0] = key, recipient[1] = scheme
        val recipient = arrayOf("+Hi2NhW+3gHCUz55GFIu7zVMg9x5WjSZoKhPukob2RE=", "symmetic-group-shared-key-for-example")

        Log.d("Test slot", "####################")

        val key_slot = identity.slot(msg_key, feed_id, prev_msg_id, Base64.decode(recipient[0], 0), recipient[1])
        //key_slot?.let { String(it) }?.let { Log.d("Test sl key_slot", it) }
        Log.d("Test sl key_slot", Base64.encodeToString(key_slot, 0))
        Log.d("Test sl key_slot has to be", "mUrryRwKhEEo4mFx9NTEUKNezIJ4pUUfoDRHiljyUOQ=")
    }


    fun unslotTest(){

        val key_slot = Base64.decode("MIVQFqZXFgADW9tvTcWXDCdm90enpy8TSxKybQ4qxGI=",0)
        val feed_id = Base64.decode("AAAew3905XdfryUoCZkgP4rowDkrzzyxBPDH/ZtIDMzUzw==",0)
        val prev_msg_id = Base64.decode("AQANw92HovBPgaGzVh6+9M9KvwZXoLYm5c4n0OOtiOP5/w==",0)

        //recipient[0] = key, recipient[1] = scheme
        val recipient = arrayOf("TMeIncVj/YECjSSthZjfD7OFWonqYR2nPXKacfbE3ck=", "symmetic-group-shared-key-for-example")

        Log.d("Test unslot", "####################")

        val msg_key = identity.unslot(key_slot, feed_id, prev_msg_id, Base64.decode(recipient[0],0), recipient[1])
        Log.d("Test usl msg_key", Base64.encodeToString(msg_key, 0))
        Log.d("Test usl msg_key has to be", "YXVQ/8mmtabyajATK8tNbrq7q8L9Q7ecYU+9JB8Zebg=")
    }

    fun boxTest(){

        val plain_text = "c3F1ZWFtaXNoIG9zc2lmcmFnZSDwn5io"
        val feed_id = Base64.decode("AACv6zOVZsd3N5mVYJs7MnmMRu08DfGmqG70+0mL0SfHUQ==",0)
        val prev_msg_id = Base64.decode("AQBP+SmjFm1B7PJ7bSaIa3JhkqMYdmlIKUtodYfE9o8/qw==",0)
        val msg_key = Base64.decode("Sio94NHxP3k+Svx7d1VReGxHdh2T9wssofb1v7Lt9ao=",0)

        //recipient[0] = key, recipient[1] = scheme
        val recipient1 = arrayOf("gVv33+Jo5348A1XJrA+hoMxYiee13QlxNpm88yHwzRY=", "envelope-large-symmetric-group")
        val recipient2 = arrayOf("beAVypscgWbDyQw6oDUwX9Huf/5dwrlhE/OrStRsU0g=", "envelope-id-based-dm-converted-ed25519")
        val rcps = arrayOf(recipient1, recipient2)

        Log.d("Test box1", "####################")

        val ciphertext = identity.encryptGroupMessage(plain_text, feed_id, prev_msg_id, rcps, msg_key)
        if (ciphertext == null){
            Log.d("Test errorcode", "boxEmptyPlainText")
        } else {
            Log.d("Test box output", ciphertext.removeSuffix(".box2"))
        }

        Log.d("Test box output has to be", "l0dEDrXwMx1VcKbnhrRy51jAtWyg5F23/6TZjWu00FyaNA+yTiRvO16ht93L18NmNWy1/KyjgKm++aiVqlE7sCqRT62OxLopHXVes/lWH9S97fhZHKCZg/vxZgdIkpefvNl/qsHerry0SnS7m5OoffpyE0wYzKqUbcMHnUyFAbtmgFvj69f+Ng==")

    }

    fun box2Test(){

        val plain_text = ""
        val feed_id = Base64.decode("AAAsgcjnPAOQSxcM4kFD7S3iDmZv+8BUqqHd+pWopMo9ZA==",0)
        val prev_msg_id = Base64.decode("AQAuUdkuV7hY0W7fnJKrXrXDcbYjs1VTj+b8ely7flfzQQ==",0)
        val msg_key = Base64.decode("DJ6Y4HJu90aGLWKAvNFZTZQEo+vAjcuQ5GVS34n1TUI=",0)

        //recipient[0] = key, recipient[1] = scheme
        val recipient1 = arrayOf("r2m7cwbK2vdcBV/vngvnLqvKGWeRl6PLsxLYJUjxB5s=", "envelope-large-symmetric-group")
        val rcps = arrayOf(recipient1)

        Log.d("Test box2", "####################")

        val ciphertext = identity.encryptGroupMessage(plain_text, feed_id, prev_msg_id, rcps, msg_key)
        if (ciphertext == null){
            Log.d("Test errorcode", "boxEmptyPlainText")
            Log.d("Test box output", "null")
        } else {
            Log.d("Test box output", ciphertext.removeSuffix(".box2"))
        }

        Log.d("Test box output has to be", "null")
    }


    fun unboxTest(){

        val ciphertext = "3vPbCVhpqGNA2x2LprhFY8nsredozkaD4FEqDOsWUIAOkhDx1SHWWGCgtmZF+e7P2jrDhISK4Tj2NXVcnAZOjqU56TPng+h8XTuX5vDLTBCJNBIzHppPCaP7J4VbMuimS2FL5bK9GgALiAFRE6vC0Z0etOIr6UQaTUXEsqhFrHGi45w+/v26gQ=="
        val feed_id = Base64.decode("AAAIySIfYP3XRy0E48Sciab/e17/A3q4EIzIu+bH+zcr7w==",0)
        val prev_msg_id = Base64.decode("AQATlcKL4zg44za93913mM2uL4rSAuM5xPZawBg5d+i9gw==",0)

        //recipient[0] = key, recipient[1] = scheme
        val recipient = arrayOf("icCRi3dmiBF+MAUE1juBqgzzUbbzQq5IkYKGnMr37Ic=",  "envelope-id-based-dm-converted-ed25519")

        Log.d("Test unbox", "####################")

        val plain_text = identity.decryptGroupMessage(ciphertext, feed_id, prev_msg_id, Base64.decode(recipient[0],0), recipient[1])

        plain_text?.let { Base64.encodeToString(it,0) }?.let { Log.d("Test ubox plain_text", it) }
        Log.d("Test ubox plain_text has to be", "c3F1ZWFtaXNoIG9zc2lmcmFnZSDwn5io")
    }

    fun cloakedMsgIdTest(){

        val public_msg_id = Base64.decode("AQCNWx2fFuNuL70fylieKWgvE8gpOLIwZ+pWcZW68VdKHg==",0)
        val read_key = Base64.decode("PARfkPyOdMNmyi3ZVAThFrPSPZAvE6yohSJRg+snvb4=",0)

        Log.d("Test cloakedMessageID", "####################")

        val cloaked_msg_id = identity.getCloakedMsgID(public_msg_id, read_key)
        Log.d("Test cid", Base64.encodeToString(cloaked_msg_id,0))
        Log.d("Test cid has to be", "uRCvZ9jW7ouuBdygpmuolyD8iubre+wYU0rf3vHdCiY=")
    }

}
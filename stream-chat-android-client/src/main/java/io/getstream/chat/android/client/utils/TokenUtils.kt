/*
 * Copyright (c) 2014-2022 Stream.io Inc. All rights reserved.
 *
 * Licensed under the Stream License;
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    https://github.com/GetStream/stream-chat-android/blob/main/LICENSE
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.getstream.chat.android.client.utils

import android.util.Base64
import io.getstream.log.taggedLogger
import org.json.JSONException
import org.json.JSONObject
import java.nio.charset.StandardCharsets

import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.SignedJWT
import io.ethers.core.types.Address
import io.ethers.crypto.Secp256k1
import org.bouncycastle.jce.provider.BouncyCastleProvider
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.core.JsonProcessingException;

internal object TokenUtils {

    val logger by taggedLogger("Chat:TokenUtils")
    fun getUserId(token: String): String? {

        val jwt: SignedJWT
        val publicKey: JWK?
        var addressFromToken: String?=null

        try {
            jwt = SignedJWT.parse(token)
            publicKey = jwt.header.jwk
            if (publicKey == null) {
                throw Exception("Token validation failed: Unknown publicKey")
            }
            if (publicKey is ECKey) {
                val verifier: JWSVerifier = ECDSAVerifier(publicKey as ECKey?)
                verifier.jcaContext.provider = BouncyCastleProvider()
                if (!jwt.verify(verifier)) {
                    throw Exception("Signature check failed: Invalid token signature")
                }
            } else {
                throw Exception("publicKey is not type of ECKey")
            }
            addressFromToken = publicKeyToAddress(publicKey)
        } catch (e: Exception) {
            logger.e(e) {"token verification failure"}
        } finally {
            return addressFromToken
        }
    }

    private fun publicKeyToAddress(publicKey: JWK): String? {
        val UNCOMPRESSED_KEY_FLAG = (0x04).toByte()
        val objectMapper = ObjectMapper()
        var jsonNode: JsonNode? = try {
            objectMapper.readTree(publicKey.toJSONString())
        } catch (e: JsonProcessingException) {
            e.printStackTrace()
            return null
        }

        val xBase64 = Base64URL.from(jsonNode!!.get("x").toString())
        val xBytes = xBase64.decode()

        val yBase64 = Base64URL.from(jsonNode!!.get("y").toString())
        val yBytes = yBase64.decode()

        val compressKey = byteArrayOf(UNCOMPRESSED_KEY_FLAG) + xBytes + yBytes
        val address = Address(Secp256k1.publicKeyToAddress(compressKey))
        return address.toString()
    }

    fun getUserId1(token: String): String = try {
        JSONObject(
            token
                .takeIf { it.contains(".") }
                ?.split(".")
                ?.getOrNull(1)
                ?.let { String(Base64.decode(it.toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP)) }
                ?: "",
        ).optString("user_id")
    } catch (e: JSONException) {
        logger.e(e) { "Unable to obtain userId from JWT Token Payload" }
        ""
    } catch (e: IllegalArgumentException) {
        logger.e(e) { "Unable to obtain userId from JWT Token Payload" }
        ""
    }

    /**
     * Generate a developer token that can be used to connect users while the app is using a development environment.
     *
     * @param userId the desired id of the user to be connected.
     */
    fun devToken(userId: String): String {
        require(userId.isNotEmpty()) { "User id must not be empty" }
        val header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" //  {"alg": "HS256", "typ": "JWT"}
        val devSignature = "devtoken"
        val payload: String =
            Base64.encodeToString("{\"user_id\":\"$userId\"}".toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP)
        return "$header.$payload.$devSignature"
    }
}

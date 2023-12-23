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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.web3j.crypto.Keys;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.math.BigInteger;

internal object TokenUtils {

    val logger by taggedLogger("Chat:TokenUtils")

    fun getUserId(token: String): String {
        val jwt: SignedJWT
        val publicKey: JWK?
        val addressFromToken: String
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
            return ""
        }

        return addressFromToken
    }
    private fun publicKeyToAddress(publicKey: JWK): String {
        val objectMapper = ObjectMapper()
        var jsonNode: JsonNode? = null
        try {
            jsonNode = objectMapper.readTree(publicKey.toJSONString())
        } catch (e: JsonProcessingException) {
            e.printStackTrace()
            throw RuntimeException(e)
            return ""
        }
        val yBase64: Base64URL = Base64URL.from(jsonNode.get("y").toString())
        val yBytes: ByteArray = yBase64.decode()
        val yHexStr = bytesToHex(yBytes)
        val xBase64: Base64URL = Base64URL.from(jsonNode.get("x").toString())
        val xBytes: ByteArray = xBase64.decode()
        val xHexStr = bytesToHex(xBytes)
        val publicKeyHexStr = xHexStr + yHexStr
        val publicKeyBig = BigInteger(publicKeyHexStr, 16)
        return Keys.getAddress(publicKeyBig)
    }

    // Convert raw bytes to hexadecimal string
    private fun bytesToHex(bytes: ByteArray): String {
        val hexString = StringBuilder()
        for (b in bytes) {
            val hex = String.format("%02x", b)
            hexString.append(hex)
        }
        return hexString.toString()
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

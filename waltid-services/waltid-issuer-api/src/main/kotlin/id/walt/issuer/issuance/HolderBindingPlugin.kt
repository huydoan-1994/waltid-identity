package id.walt.issuer.issuance

import id.walt.oid4vc.definitions.JWTClaims
import id.walt.oid4vc.errors.CredentialError
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.responses.CredentialErrorCode
import id.walt.oid4vc.util.JwtUtils
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.serialization.json.*
import java.security.MessageDigest
import java.util.Base64

/**
 * Validates that the holder presenting the proof JWT at credential time
 * matches the expected holder DID bound at offer creation time.
 *
 * Uses JWK Thumbprint (RFC 7638) for comparison to avoid encoding mismatches
 * between different did:jwk representations.
 */
object HolderBindingPlugin {

    private val log = KotlinLogging.logger { }

    fun validateHolderBinding(
        session: IssuanceSession,
        credentialRequest: CredentialRequest,
    ) {
        val expectedHolderDid = session.customParameters
            ?.get("expectedHolderDid")
            ?.jsonPrimitive?.contentOrNull
            ?: return // No binding configured — skip validation

        val proofJwt = credentialRequest.proof?.jwt
            ?: throw CredentialError(
                credentialRequest = credentialRequest,
                errorCode = CredentialErrorCode.invalid_or_missing_proof,
                message = "Proof must be JWT proof"
            )

        val proofHeader = JwtUtils.parseJWTHeader(proofJwt)

        val holderKid = proofHeader[JWTClaims.Header.keyID]?.jsonPrimitive?.contentOrNull
        val holderJwk = proofHeader[JWTClaims.Header.jwk]?.jsonObject

        val proofThumbprint = when {
            holderJwk != null -> computeJwkThumbprint(holderJwk)
            holderKid != null && holderKid.startsWith("did:jwk:") -> {
                val jwk = resolveJwkFromDidJwk(holderKid)
                computeJwkThumbprint(jwk)
            }
            else -> throw CredentialError(
                credentialRequest = credentialRequest,
                errorCode = CredentialErrorCode.invalid_or_missing_proof,
                message = "Cannot extract holder key from proof for binding validation"
            )
        }

        val expectedThumbprint = computeThumbprintFromDid(expectedHolderDid)

        if (proofThumbprint != expectedThumbprint) {
            log.warn { "Holder binding mismatch: expected=$expectedThumbprint, got=$proofThumbprint, expectedDid=$expectedHolderDid" }
            throw CredentialError(
                credentialRequest = credentialRequest,
                errorCode = CredentialErrorCode.invalid_or_missing_proof,
                message = "Holder DID does not match the expected binding for this credential offer"
            )
        }

        log.debug { "Holder binding validated successfully for session=${session.id}" }
    }

    /**
     * Compute JWK Thumbprint per RFC 7638 using SHA-256.
     * For EC keys: canonical form is {"crv":...,"kty":...,"x":...,"y":...} (alphabetical).
     */
    internal fun computeJwkThumbprint(jwk: JsonObject): String {
        val kty = jwk["kty"]?.jsonPrimitive?.content
            ?: throw IllegalArgumentException("JWK missing 'kty'")

        val canonicalJson = when (kty) {
            "EC" -> {
                val crv = jwk["crv"]?.jsonPrimitive?.content ?: throw IllegalArgumentException("EC JWK missing 'crv'")
                val x = jwk["x"]?.jsonPrimitive?.content ?: throw IllegalArgumentException("EC JWK missing 'x'")
                val y = jwk["y"]?.jsonPrimitive?.content ?: throw IllegalArgumentException("EC JWK missing 'y'")
                """{"crv":"$crv","kty":"$kty","x":"$x","y":"$y"}"""
            }
            "OKP" -> {
                val crv = jwk["crv"]?.jsonPrimitive?.content ?: throw IllegalArgumentException("OKP JWK missing 'crv'")
                val x = jwk["x"]?.jsonPrimitive?.content ?: throw IllegalArgumentException("OKP JWK missing 'x'")
                """{"crv":"$crv","kty":"$kty","x":"$x"}"""
            }
            "RSA" -> {
                val e = jwk["e"]?.jsonPrimitive?.content ?: throw IllegalArgumentException("RSA JWK missing 'e'")
                val n = jwk["n"]?.jsonPrimitive?.content ?: throw IllegalArgumentException("RSA JWK missing 'n'")
                """{"e":"$e","kty":"$kty","n":"$n"}"""
            }
            else -> throw IllegalArgumentException("Unsupported key type: $kty")
        }

        val digest = MessageDigest.getInstance("SHA-256").digest(canonicalJson.toByteArray(Charsets.UTF_8))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }

    /**
     * Resolve the public JWK from a did:jwk identifier.
     * did:jwk:<base64url-encoded-jwk>[#0]
     */
    internal fun resolveJwkFromDidJwk(didJwk: String): JsonObject {
        val didPart = didJwk.removePrefix("did:jwk:").substringBefore("#")
        val decoded = Base64.getUrlDecoder().decode(didPart).toString(Charsets.UTF_8)
        return Json.parseToJsonElement(decoded).jsonObject
    }

    /**
     * Compute the JWK Thumbprint from a DID.
     * Supports did:jwk (decodes the embedded JWK).
     */
    private fun computeThumbprintFromDid(did: String): String {
        return when {
            did.startsWith("did:jwk:") -> {
                val jwk = resolveJwkFromDidJwk(did)
                computeJwkThumbprint(jwk)
            }
            else -> throw IllegalArgumentException(
                "Unsupported DID method for holder binding: $did. Only did:jwk is supported."
            )
        }
    }
}

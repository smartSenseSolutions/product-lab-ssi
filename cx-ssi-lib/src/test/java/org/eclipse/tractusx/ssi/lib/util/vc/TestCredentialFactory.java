package org.eclipse.tractusx.ssi.lib.util.vc;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import lombok.SneakyThrows;
import org.eclipse.tractusx.ssi.lib.model.proof.Proof;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.*;
import org.eclipse.tractusx.ssi.lib.util.identity.TestIdentity;

public class TestCredentialFactory {

  @SneakyThrows
  public static VerifiableCredential createCredential(TestIdentity issuer, Proof proof) {
    VerifiableCredentialBuilder verifiableCredentialBuilder = new VerifiableCredentialBuilder();

    VerifiableCredentialSubject verifiableCredentialSubject =
        new VerifiableCredentialSubject(Map.of("foo", "bar"));

    // add VC status
    String validStatus =
        "{\n"
            + "    \"id\": \"https://example.com/credentials/status/3#94567\",\n"
            + "    \"type\": \"StatusList2021Entry\",\n"
            + "    \"statusPurpose\": \"revocation\",\n"
            + "    \"statusListIndex\": \"94567\",\n"
            + "    \"statusListCredential\": \"https://example.com/credentials/status/3\"\n"
            + "  }";
    ObjectMapper objectMapper = new ObjectMapper();
    Map<String, Object> statusMap = objectMapper.readValue(validStatus, Map.class);
    VerifiableCredentialStatusList2021Entry verifiableCredentialStatusList2021Entry =
        new VerifiableCredentialStatusList2021Entry(statusMap);

    return verifiableCredentialBuilder
        .id(URI.create("did:test:id"))
        .type(List.of(VerifiableCredentialType.VERIFIABLE_CREDENTIAL))
        .issuer(issuer.getDid().toUri())
        .expirationDate(Instant.parse("2025-02-15T17:21:42Z").plusSeconds(3600))
        .issuanceDate(Instant.parse("2023-02-15T17:21:42Z"))
        .proof(proof)
        .credentialSubject(verifiableCredentialSubject)
        .verifiableCredentialStatus(verifiableCredentialStatusList2021Entry)
        .build();
  }

  public static VerifiableCredential attachProof(
      VerifiableCredential verifiableCredential, Proof proof) {
    VerifiableCredentialBuilder verifiableCredentialBuilder = new VerifiableCredentialBuilder();

    return verifiableCredentialBuilder
        .id(verifiableCredential.getId())
        .type(verifiableCredential.getTypes())
        .issuer(verifiableCredential.getIssuer())
        .expirationDate(verifiableCredential.getExpirationDate())
        .issuanceDate(verifiableCredential.getIssuanceDate())
        .proof(proof)
        .credentialSubject(verifiableCredential.getCredentialSubject())
        .verifiableCredentialStatus(verifiableCredential.getVerifiableCredentialStatus())
        .build();
  }
}

/********************************************************************************
 * Copyright (c) 2021,2023 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License, Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

package org.eclipse.tractusx.ssi.lib.proof;

import org.eclipse.tractusx.ssi.lib.exception.DidDocumentResolverNotRegisteredException;
import org.eclipse.tractusx.ssi.lib.exception.InvalidePublicKeyFormat;
import org.eclipse.tractusx.ssi.lib.exception.NoVerificationKeyFoundExcpetion;
import org.eclipse.tractusx.ssi.lib.exception.UnsupportedSignatureTypeException;
import org.eclipse.tractusx.ssi.lib.model.did.Did;
import org.eclipse.tractusx.ssi.lib.model.verifiable.credential.VerifiableCredential;
import org.eclipse.tractusx.ssi.lib.model.verifiable.presentation.VerifiablePresentation;
import org.eclipse.tractusx.ssi.lib.proof.hash.HashedLinkedData;

public interface IVerifier {
 /**
  * {@link VerifiableCredential} verification method,
  * This method depends on Issuer in VC data model to get the public key of issuer.
  *
  * @param hashedLinkedData
  * @param document {@link VerifiableCredential}
  */

  public boolean verify(HashedLinkedData hashedLinkedData, VerifiableCredential document)
      throws UnsupportedSignatureTypeException, DidDocumentResolverNotRegisteredException,
          InvalidePublicKeyFormat, NoVerificationKeyFoundExcpetion;
 /**
  * {@link VerifiablePresentation} verification method,
  * This method depends on issuer parameter to get the public key of issuer.
  *
  * @param hashedLinkedData
  * @param document {@link VerifiableCredential}
  * @param issuer {@link DID}
  */

   public boolean verify(HashedLinkedData hashedLinkedData, VerifiablePresentation document, Did issuer)
      throws UnsupportedSignatureTypeException, DidDocumentResolverNotRegisteredException,
          InvalidePublicKeyFormat, NoVerificationKeyFoundExcpetion;

}

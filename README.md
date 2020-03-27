# Cryptographie-BouncyCastle-Java

## Cryptographie symétrique/asymétrique
### Symétrique
  * Génération d'une clé (Rijndael, CBC)
  * Chiffrement
  * Déchiffrement
### Asymétrique
  * Génération d'une paire de clé (RSA 1024 bits)
  * Chiffrement
  * Déchiffrement

## Authorité de certification
### Simulation du comportement d'une PKI (Public Key Infrastructure)
  * Un CA (Certificate Authority) capable de traiter les demandes de certification reçues des utilisateurs et, s'ils sont
corrects, délivre les certificats de clé publique correspondants.
  * Un utilisateurs qui génère une demande de certifcation (possède également une méthode pour vérifier la validité d'un certificat en se basant sur la date et la signature du CA)

(Code réalisé dans le cadre de cours suivis à l'Université Polytechnique de Madrid)

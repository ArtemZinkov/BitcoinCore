import Foundation
import HsCryptoKit
import HsExtensions
import HdWalletKit

class SchnorrInputSigner {
    enum SignError: Error {
        case noPreviousOutput
        case noPreviousOutputAddress
        case noPrivateKey
    }

    let hdWallet: IPrivateHDWallet

    init(hdWallet: IPrivateHDWallet) {
        self.hdWallet = hdWallet
    }

}

extension SchnorrInputSigner: IInputSigner {
    
    func prepareDataForSigning(mutableTransaction: MutableTransaction, index: Int) throws -> [Data] {
        let input = mutableTransaction.inputsToSign[index]
        let pubKey = input.previousOutputPublicKey
        
        let serializedTransaction = try TransactionSerializer.serializedForTaprootSignature(
            transaction: mutableTransaction.transaction,
            inputsToSign: mutableTransaction.inputsToSign,
            outputs: mutableTransaction.outputs,
            inputIndex: index
        )

        let signatureHash = try SchnorrHelper.hashTweak(data: serializedTransaction, tag: "TapSighash")
        return [signatureHash]
    }
    
    func sigScriptData(transaction: Transaction, inputsToSign: [InputToSign], outputs: [Output], index: Int) throws -> [Data] {
        let input = inputsToSign[index]
        let pubKey = input.previousOutputPublicKey

        guard let privateKeyData = try? hdWallet.privateKeyData(account: pubKey.account, index: pubKey.index, external: pubKey.external) else {
            throw SignError.noPrivateKey
        }

        let serializedTransaction = try TransactionSerializer.serializedForTaprootSignature(
            transaction: transaction,
            inputsToSign: inputsToSign,
            outputs: outputs,
            inputIndex: index
        )

        let signatureHash = try SchnorrHelper.hashTweak(data: serializedTransaction, tag: "TapSighash")
        let signature = try SchnorrHelper.sign(data: signatureHash, privateKey: privateKeyData, publicKey: pubKey.raw)

        return [signature]
    }

    func sigScriptData(mutableTransaction: MutableTransaction, index: Int) throws -> [Data] {
        return try sigScriptData(
            transaction: mutableTransaction.transaction,
            inputsToSign: mutableTransaction.inputsToSign,
            outputs: mutableTransaction.outputs,
            index: index
        )
    }

}

import Foundation
import HsCryptoKit
import HsExtensions
import HdWalletKit

class EcdsaInputSigner {
    enum SignError: Error {
        case noPreviousOutput
        case noPreviousOutputAddress
        case noPrivateKey
    }

    let hdWallet: IPrivateHDWallet
    let network: INetwork

    init(hdWallet: IPrivateHDWallet, network: INetwork) {
        self.hdWallet = hdWallet
        self.network = network
    }

}

extension EcdsaInputSigner: IInputSigner {
    
    func prepareDataForSigning(mutableTransaction: MutableTransaction, index: Int) throws -> [Data] {
        let input = mutableTransaction.inputsToSign[index]
        let previousOutput = input.previousOutput
        let pubKey = input.previousOutputPublicKey
        
        let witness = previousOutput.scriptType == .p2wpkh || previousOutput.scriptType == .p2wpkhSh
        
        var serializedTransaction = try TransactionSerializer.serializedForSignature(
            transaction: mutableTransaction.transaction,
            inputsToSign: mutableTransaction.inputsToSign,
            outputs: mutableTransaction.outputs,
            inputIndex: index,
            forked: witness || network.sigHash.forked
        )
        serializedTransaction += UInt32(network.sigHash.value)
        let signatureHash = Crypto.doubleSha256(serializedTransaction)
        let network = Data([network.sigHash.value])
        
        switch previousOutput.scriptType {
        case .p2pk: return [signatureHash, network]
        default: return [signatureHash, network, pubKey.raw]
        }
    }
    
    func sigScriptData(transaction: Transaction, inputsToSign: [InputToSign], outputs: [Output], index: Int) throws -> [Data] {
        let input = inputsToSign[index]
        let previousOutput = input.previousOutput
        let pubKey = input.previousOutputPublicKey
        let publicKey = pubKey.raw

        guard let privateKeyData = try? hdWallet.privateKeyData(account: pubKey.account, index: pubKey.index, external: pubKey.external) else {
            throw SignError.noPrivateKey
        }
        let witness = previousOutput.scriptType == .p2wpkh || previousOutput.scriptType == .p2wpkhSh

        var serializedTransaction = try TransactionSerializer.serializedForSignature(transaction: transaction, inputsToSign: inputsToSign, outputs: outputs, inputIndex: index, forked: witness || network.sigHash.forked)
        serializedTransaction += UInt32(network.sigHash.value)
        let signatureHash = Crypto.doubleSha256(serializedTransaction)
        let signature = try Crypto.sign(data: signatureHash, privateKey: privateKeyData) + Data([network.sigHash.value])

        switch previousOutput.scriptType {
        case .p2pk: return [signature]
        default: return [signature, publicKey]
        }
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

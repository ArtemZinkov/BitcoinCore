import Foundation

public typealias SigningBlock = (Data) -> Data

class TransactionSigner {
    enum SignError: Error {
        case notSupportedScriptType
        case noRedeemScript
    }

    private let ecdsaInputSigner: IInputSigner
    private let schnorrInputSigner: IInputSigner

    init(ecdsaInputSigner: IInputSigner, schnorrInputSigner: IInputSigner) {
        self.ecdsaInputSigner = ecdsaInputSigner
        self.schnorrInputSigner = schnorrInputSigner
    }

    private func signatureScript(from sigScriptData: [Data]) -> Data {
        sigScriptData.reduce(Data()) {
            $0 + OpCode.push($1)
        }
    }
    
    private func ecdsaSign(index: Int, mutableTransaction: MutableTransaction, signingBlock: SigningBlock) throws {
        let inputToSign = mutableTransaction.inputsToSign[index]
        let previousOutput = inputToSign.previousOutput
        var sigScriptData = try ecdsaInputSigner.prepareDataForSigning(
            mutableTransaction: mutableTransaction,
            index: index
        )

        let signedData = signingBlock(sigScriptData.removeFirst())

        try processEcdsaSign(index: index, mutableTransaction: mutableTransaction, signature: [signedData] + sigScriptData)
    }

    private func ecdsaSign(index: Int, mutableTransaction: MutableTransaction) throws {
        let inputToSign = mutableTransaction.inputsToSign[index]
        let previousOutput = inputToSign.previousOutput
        var sigScriptData = try ecdsaInputSigner.sigScriptData(
            mutableTransaction: mutableTransaction,
            index: index
        )

        try processEcdsaSign(index: index, mutableTransaction: mutableTransaction, signature: sigScriptData)
    }
    
    private func processEcdsaSign(index: Int, mutableTransaction: MutableTransaction, signature: [Data]) throws {
        let inputToSign = mutableTransaction.inputsToSign[index]
        let previousOutput = inputToSign.previousOutput
        var sigScriptData = signature

        switch previousOutput.scriptType {
            case .p2pkh:
                inputToSign.input.signatureScript = signatureScript(from: sigScriptData)
            case .p2wpkh:
                mutableTransaction.transaction.segWit = true
                inputToSign.input.witnessData = sigScriptData
            case .p2wpkhSh:
                mutableTransaction.transaction.segWit = true
                let publicKey = inputToSign.previousOutputPublicKey
                inputToSign.input.witnessData = sigScriptData
                inputToSign.input.signatureScript = OpCode.push(OpCode.segWitOutputScript(publicKey.hashP2pkh, versionByte: 0))
            case .p2sh:
                guard let redeemScript = previousOutput.redeemScript else {
                    throw SignError.noRedeemScript
                }

                if let signatureScriptFunction = previousOutput.signatureScriptFunction {
                    // non-standard P2SH signature script
                    inputToSign.input.signatureScript = signatureScriptFunction(sigScriptData)
                } else {
                    // standard (signature, publicKey, redeemScript) signature script
                    sigScriptData.append(redeemScript)
                    inputToSign.input.signatureScript = signatureScript(from: sigScriptData)
                }
            default: throw SignError.notSupportedScriptType
        }
    }

    private func schnorrSign(index: Int, mutableTransaction: MutableTransaction, signingBlock: SigningBlock) throws {
        let inputToSign = mutableTransaction.inputsToSign[index]
        let previousOutput = inputToSign.previousOutput

        guard previousOutput.scriptType == .p2tr else {
            throw SignError.notSupportedScriptType
        }

        var witnessData = try schnorrInputSigner.prepareDataForSigning(
            mutableTransaction: mutableTransaction,
            index: index
        )
        
        let signedData = signingBlock(witnessData.removeFirst())

        mutableTransaction.transaction.segWit = true
        inputToSign.input.witnessData = [signedData]
    }

    private func schnorrSign(index: Int, mutableTransaction: MutableTransaction) throws {
        let inputToSign = mutableTransaction.inputsToSign[index]
        let previousOutput = inputToSign.previousOutput

        guard previousOutput.scriptType == .p2tr else {
            throw SignError.notSupportedScriptType
        }

        let witnessData = try schnorrInputSigner.sigScriptData(
            mutableTransaction: mutableTransaction,
            index: index
        )

        mutableTransaction.transaction.segWit = true
        inputToSign.input.witnessData = witnessData
    }
}

extension TransactionSigner: ITransactionSigner {

    func sign(mutableTransaction: MutableTransaction) throws {
        for (index, inputToSign) in mutableTransaction.inputsToSign.enumerated() {
            if inputToSign.previousOutput.scriptType == .p2tr {
                try schnorrSign(index: index, mutableTransaction: mutableTransaction)
            } else {
                try ecdsaSign(index: index, mutableTransaction: mutableTransaction)
            }
        }
    }

    func sign(mutableTransaction: MutableTransaction, signingBlock: SigningBlock) throws {
        for (index, inputToSign) in mutableTransaction.inputsToSign.enumerated() {
            if inputToSign.previousOutput.scriptType == .p2tr {
                try schnorrSign(index: index, mutableTransaction: mutableTransaction, signingBlock: signingBlock)
            } else {
                try ecdsaSign(index: index, mutableTransaction: mutableTransaction, signingBlock: signingBlock)
            }
        }
    }
}

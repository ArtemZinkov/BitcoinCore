import Foundation

class TransactionCreator {
    enum CreationError: Error {
        case transactionAlreadyExists
    }

    private let transactionBuilder: ITransactionBuilder

    init(transactionBuilder: ITransactionBuilder) {
        self.transactionBuilder = transactionBuilder
    }
}

extension TransactionCreator: ITransactionCreator {

    func create(to address: String, value: Int, feeRate: Int, senderPay: Bool, sortType: TransactionDataSortType, pluginData: [UInt8: IPluginData] = [:], forceSign: Bool) throws -> FullTransaction {
        let transaction = try transactionBuilder.buildTransaction(
            toAddress: address,
            value: value,
            feeRate: feeRate,
            senderPay: senderPay,
            sortType: sortType,
            pluginData: pluginData,
            forceSign: forceSign
        )

        return transaction
    }

    func create(from unspentOutput: UnspentOutput, to address: String, feeRate: Int, sortType: TransactionDataSortType, forceSign: Bool) throws -> FullTransaction {
        let transaction = try transactionBuilder.buildTransaction(
            from: unspentOutput,
            toAddress: address,
            feeRate: feeRate,
            sortType: sortType,
            forceSign: forceSign
        )

        return transaction
    }

    func createRawTransaction(to address: String, value: Int, feeRate: Int, senderPay: Bool, sortType: TransactionDataSortType, pluginData: [UInt8: IPluginData] = [:], forceSign: Bool) throws -> Data {
        let transaction = try transactionBuilder.buildTransaction(
            toAddress: address,
            value: value,
            feeRate: feeRate,
            senderPay: senderPay,
            sortType: sortType,
            pluginData: pluginData,
            forceSign: forceSign
        )

        return TransactionSerializer.serialize(transaction: transaction)
    }

}

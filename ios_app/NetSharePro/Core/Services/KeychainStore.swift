import Foundation
import Security

final class KeychainStore {
    private let service: String

    init(service: String) {
        self.service = service
    }

    func string(forKey key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func set(_ value: String, forKey key: String) {
        let data = Data(value.utf8)
        var searchQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        let updateAttributes: [String: Any] = [
            kSecValueData as String: data
        ]
        let updateStatus = SecItemUpdate(searchQuery as CFDictionary, updateAttributes as CFDictionary)
        if updateStatus == errSecItemNotFound {
            searchQuery[kSecValueData as String] = data
            SecItemAdd(searchQuery as CFDictionary, nil)
        }
    }

    func removeValue(forKey key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        SecItemDelete(query as CFDictionary)
    }
}

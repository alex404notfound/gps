import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Keep authentication and provisioning requests on Apple's HTTPS hosts.
enum AppleOnlyNetwork {
    static func accepts(_ url: URL) -> Bool {
        guard url.scheme?.lowercased() == "https", let host = url.host?.lowercased() else {
            return false
        }
        return host == "apple.com" || host.hasSuffix(".apple.com")
    }

    static let session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 60
        return URLSession(configuration: configuration,
                          delegate: AppleOnlyRedirectGuard(),
                          delegateQueue: nil)
    }()
}

private final class AppleOnlyRedirectGuard: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(request.url.map(AppleOnlyNetwork.accepts) == true ? request : nil)
    }
}

# swift-oauth2-wrapper

Swift package around the OAuthSwift package with local caching and persisting of tokens to a user's Keychain. 

## Important

Work in progress. Proper documentation to follow, specifically about how to configure OAuth2 (client) crendetials and configuring (OAuth2) callbacks.

## Example

```
import OAuth2Wrapper
import OAuthSwift

func DoAuth() {

    let oauth2_id = "myapp://access_token"
    let oauth2_callback_url = "myapp://oauth2"

    let wrapper = OAuth2Wrapper(id: oauth2_id, callback_url: oauth2_callback_url)
    wrapper.GetAccessToken(completion: GotAuth)
}

func GotAuth(result: Result<OAuthSwiftCredential, Error>){

    switch result {
    case .failure(let error):
        print(error)
    case .success(let creds):
        print(creds.oauthToken)
    }
}

## See also

* https://github.com/OAuthSwift/OAuthSwift
* https://github.com/jrendel/SwiftKeychainWrapper

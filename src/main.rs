use std::{
    env,
    str::FromStr,
    time::{self, SystemTime},
};

use alloy::{
    primitives::{Address, Bytes, FixedBytes, U64, U256, bytes, keccak256},
    signers::Signer,
};
use alloy_signer_local::PrivateKeySigner;
use jsonrpsee::{http_client::HttpClient, proc_macros::rpc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv()?;

    let api_key = env::var("API_KEY")?;
    let chain_id = U64::from(421614); // Arb Sepolia

    let alchemy_url = format!("https://api.g.alchemy.com/v2/{api_key}");
    let client = HttpClient::builder().build(alchemy_url)?;

    let owner_signer = PrivateKeySigner::from_bytes(&keccak256("dphil_owner"))?;
    let session_signer = PrivateKeySigner::from_bytes(&keccak256("dphil_session123"))?;

    let expiry = U64::from(
        SystemTime::now()
            .duration_since(time::UNIX_EPOCH)?
            .as_secs()
            - 60 * 60 * 24 * 30, // 30 days
    );

    let account_response = client
        .request_account(RequestAccountRequest {
            signer_address: owner_signer.address(),
        })
        .await?;

    let session_response = client
        .create_session(CreateSessionRequest {
            account: account_response.account_address,
            chain_id,
            expiry,
            key: Key {
                public_key: session_signer.address(),
                r#type: "secp256k1".to_string(),
            },
            permissions: vec![
                Permission::NativeTokenTransfer {
                    allowance: U64::from(1),
                },
                Permission::FunctionsOnAllContracts {
                    functions: vec![FixedBytes::from_str("0xddf252ad")?],
                },
            ],
        })
        .await?;

    let signature = owner_signer
        .sign_dynamic_typed_data(&serde_json::from_value(
            session_response.signature_request.data,
        )?)
        .await?;

    let context = format!(
        "0x00{}{}",
        &session_response.session_id[2..],
        &signature.to_string()[2..],
    );

    let capabilities = Capabilities {
        paymaster_service: PaymasterService {
            policy_id: env::var("PAYMASTER_POLICY_ID")?,
        },
        permissions: CapabilitiesPermissions { context },
    };

    let prepare_req = PrepareCallsRequest {
        capabilities: capabilities.clone(),
        calls: vec![Call {
            to: Address::ZERO,
            data: bytes!("0xddf252ad"),
        }],
        from: account_response.account_address,
        chain_id,
    };

    let prepare_calls_response = client.prepare_calls(prepare_req).await?;

    let hash_to_sign = prepare_calls_response.signature_request.data.raw;

    let signature = session_signer
        .sign_message(&hash_to_sign)
        .await?
        .to_string();

    let send_prepared_calls_request = SendPreparedCallsRequest {
        r#type: prepare_calls_response.r#type,
        chain_id,
        data: prepare_calls_response.data,
        capabilities,
        signature: SignatureObject {
            r#type: "secp256k1".to_string(),
            signature,
        },
    };

    let send_prepared_calls_response = client
        .send_prepared_calls(send_prepared_calls_request)
        .await?;

    dbg!(send_prepared_calls_response);

    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestAccountRequest {
    signer_address: Address,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestAccountResponse {
    account_address: Address,
    id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateSessionRequest {
    account: Address,
    chain_id: U64,
    expiry: U64,
    key: Key,
    permissions: Vec<Permission>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Key {
    public_key: Address,
    r#type: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", tag = "type", content = "data")]
enum Permission {
    /// full root permissions (no data)
    Root,

    /// allow up to a specified allowance
    NativeTokenTransfer { allowance: U64 },

    /// transfer ERC20 tokens up to allowance
    Erc20TokenTransfer { address: Address, allowance: U64 },

    /// set a maximum gas limit
    GasLimit { limit: U256 },

    /// allow arbitrary contract calls (no data)
    ContractAccess { address: Address },

    /// allowed functions on the user’s own account
    AccountFunctions { functions: Vec<FixedBytes<4>> },

    /// allow calls to specific functions on any contract
    FunctionsOnAllContracts { functions: Vec<FixedBytes<4>> },

    /// allow calls to specific functions on a single contract
    FunctionsOnContract {
        address: Address,
        functions: Vec<FixedBytes<4>>,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateSessionResponse {
    session_id: String,
    signature_request: TypedDataSignatureRequest,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TypedDataSignatureRequest {
    r#type: String,
    data: Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PrepareCallsRequest {
    capabilities: Capabilities,
    calls: Vec<Call>,
    from: Address,
    chain_id: U64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Capabilities {
    paymaster_service: PaymasterService,
    permissions: CapabilitiesPermissions,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PaymasterService {
    policy_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CapabilitiesPermissions {
    context: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Call {
    to: Address,
    data: Bytes,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PrepareCallsResponse {
    r#type: String,
    data: Value,
    chain_id: U64,
    signature_request: RawSignatureRequest,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct RawSignatureRequest {
    r#type: String,
    data: RawData,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct RawData {
    raw: Bytes,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SendPreparedCallsRequest {
    r#type: String,
    chain_id: U64,
    data: Value,
    capabilities: Capabilities,
    signature: SignatureObject,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SendPreparedCallsResponse {
    prepared_call_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignatureObject {
    r#type: String,
    signature: String,
}
#[rpc(client, namespace = "wallet")]
trait WalletRpc {
    #[method(name = "requestAccount")]
    async fn request_account(
        &self,
        request: RequestAccountRequest,
    ) -> Result<RequestAccountResponse, ErrorObjectOwned>;

    #[method(name = "createSession")]
    async fn create_session(
        &self,
        request: CreateSessionRequest,
    ) -> Result<CreateSessionResponse, ErrorObjectOwned>;

    #[method(name = "prepareCalls")]
    async fn prepare_calls(
        &self,
        request: PrepareCallsRequest,
    ) -> Result<PrepareCallsResponse, ErrorObjectOwned>;

    #[method(name = "sendPreparedCalls")]
    async fn send_prepared_calls(
        &self,
        request: SendPreparedCallsRequest,
    ) -> Result<SendPreparedCallsResponse, ErrorObjectOwned>;
}

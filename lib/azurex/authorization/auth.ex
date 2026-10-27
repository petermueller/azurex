defmodule Azurex.Authorization.Auth do
  alias Azurex.Blob.Config
  alias Azurex.Authorization.SharedKey
  alias Azurex.Authorization.ServicePrincipal
  alias Azurex.Authorization.ManagedIdentity

  import Azurex.Authorization.Utils

  @doc """
  Adds authentication header to a given request based on the configured auth method.

  `connection_params` may carry per-request overrides of the `Azurex.Blob.Config`
  settings, see `Azurex.Blob.Config.auth_method/1`.
  """
  @spec authorize_request(HTTPoison.Request.t(), binary(), keyword()) :: HTTPoison.Request.t()
  def authorize_request(request, content_type \\ "", connection_params \\ []) do
    case Config.auth_method(connection_params) do
      {:account_key, storage_account_key} ->
        SharedKey.sign(
          request,
          storage_account_name: Config.storage_account_name(connection_params),
          storage_account_key: storage_account_key,
          content_type: content_type
        )

      {:service_principal, client_id, client_secret, tenant} ->
        ServicePrincipal.add_bearer_token(
          request,
          client_id,
          client_secret,
          tenant
        )
        |> put_standard_headers(content_type, DateTime.utc_now())

      {:managed_identity, client_id, tenant, identity_token} ->
        request
        |> ManagedIdentity.add_bearer_token(client_id, tenant, identity_token)
        |> put_standard_headers(content_type, DateTime.utc_now())
    end
  end
end

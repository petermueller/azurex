defmodule Azurex.Blob.SharedAccessSignature do
  @moduledoc """
  Implements shared access signatures (SAS) on Blob Storage resources.
  """
  alias Azurex.Blob.SharedAccessSignature.UserDelegationSAS
  alias Azurex.Blob.SharedAccessSignature.ServiceSAS
  alias Azurex.Blob.Config

  @doc """
  Generates a SAS url on a resource.

  ## Params
  - overrides: use different configuration options for the azure connection. If the parameter is a string, it is treated as the container for backwards compatibility
  - resource: the path to the resource (blob, container, directory...)
  - opts: an optional keyword list with following options
    - resource_type: one of :blob / :blob_version / :blob_snapshot / :container / directory
      Defaults to :container
    - permissions: a list of permissions. Defaults to [:read]
    - from: a tuple to defined when the SAS url validity begins. Defaults to `now`.
    - expiry: a tuple to set how long before the SAS url expires. Defaults to `{:second, 3600}`.

  ## Examples
  - `SharedAccessSignature.sas_url("/")`
  - `SharedAccessSignature.sas_url([], "/", permissions: [:read, :write])`
  - `SharedAccessSignature.sas_url("my_container", "/", permissions: [:write], expiry: {:day, 2})`
  - `SharedAccessSignature.sas_url("my_container", "foo/song.mp3", resource_type: :blob)`
  - `SharedAccessSignature.sas_url([storage_account_connection_string: "AccountName=name;AccountKey=key", container: "my_container"], "/")`
  - `SharedAccessSignature.sas_url([storage_account_name: "name", storage_account_key: "key"], "bar/image.jpg", resource_type: :blob)`
  """
  @spec sas_url(Config.config_overrides(), String.t(), [{atom(), any()}]) :: String.t()
  def sas_url(overrides \\ [], resource, opts \\ []) do
    connection_params = Config.get_connection_params(overrides)
    base_url = Config.api_url(connection_params)
    resource_type = Keyword.get(opts, :resource_type, :container)
    permissions = Keyword.get(opts, :permissions, [:read])
    from = Keyword.get(opts, :from, DateTime.utc_now())
    expiry = Keyword.get(opts, :expiry, {:second, 3600})
    container = Keyword.get(connection_params, :container) || Config.default_container()
    resource = Path.join(container, resource)
    storage_account_name = Config.storage_account_name(connection_params)

    token =
      case Config.auth_method(connection_params) do
        {:account_key, account_key} ->
          ServiceSAS.build_token(
            resource_type,
            resource,
            {from, expiry},
            permissions,
            storage_account_name,
            account_key
          )

        {auth_method, _client_id, _tenant_id, _identity_token}
        when auth_method in [:service_principal, :managed_identity] ->
          UserDelegationSAS.build_token(
            resource_type,
            resource,
            {from, expiry},
            permissions,
            storage_account_name,
            connection_params
          )
      end

    "#{Path.join(base_url, resource)}?#{token}"
  end
end

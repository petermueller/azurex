defmodule Azurex.Blob.Config do
  @moduledoc """
  Azurex Blob Config
  """

  @type config_overrides :: String.t() | keyword

  defp conf, do: Application.get_env(:azurex, __MODULE__, [])

  @doc """
  Azure endpoint url, optional
  Defaults to `https://{name}.blob.core.windows.net` where `name` is the `storage_account_name`
  """
  @spec api_url(keyword) :: String.t()
  def api_url(connection_params \\ []) do
    Keyword.get(connection_params, :api_url) ||
      connection_string_value(connection_params, "BlobEndpoint") ||
      Keyword.get(conf(), :api_url) ||
      connection_string_value(conf(), "BlobEndpoint") ||
      "https://#{storage_account_name(connection_params)}.blob.core.windows.net"
  end

  @doc """
  Azure container name, optional.
  """
  @spec default_container :: String.t() | nil
  def default_container do
    Keyword.get(conf(), :default_container) ||
      raise "Must specify `container` because the default container was not provided."
  end

  @doc """
  Azure storage account name.
  Required if `storage_account_connection_string` not set.
  """
  @spec storage_account_name(keyword) :: String.t()
  def storage_account_name(connection_params \\ []) do
    Keyword.get(connection_params, :storage_account_name) ||
      connection_string_value(connection_params, "AccountName") ||
      Keyword.get(conf(), :storage_account_name) ||
      connection_string_value(conf(), "AccountName") ||
      raise "Azurex.Blob.Config: Missing storage account name"
  end

  @doc """
  Resolves the credentials to authenticate requests with.

  Credentials given in `connection_params` are used as a whole; when they carry none,
  the application config is used instead.
  """
  @spec auth_method(keyword) ::
          {:service_principal, binary(), binary(), binary()}
          | {:account_key, binary()}
          | {:managed_identity, binary(), binary(), binary()}
  def auth_method(connection_params \\ []) do
    resolve_auth_method(connection_params) || resolve_auth_method(conf()) ||
      raise """
      Azurex.Blob.Config: Missing credentials settings.
      Either set storage account key with: `storage_account_key` or `storage_account_connection_string`
      Or set service principal with: `storage_client_id`, `storage_client_secret` and `storage_tenant_id`
      Or set managed identity with: `storage_client_id`, `storage_tenant_id`, and `storage_identity_token`
      """
  end

  defp resolve_auth_method(settings) do
    nil
    |> try_account_key(settings)
    |> try_service_principal(settings)
    |> try_managed_identity(settings)
  end

  defp try_account_key(nil, settings) do
    case Keyword.get(settings, :storage_account_key) ||
           connection_string_value(settings, "AccountKey") do
      nil -> nil
      key -> {:account_key, Base.decode64!(key)}
    end
  end

  defp try_service_principal(nil, settings) do
    {_missing_values, values} =
      [:storage_client_id, :storage_client_secret, :storage_tenant_id]
      |> Enum.map(&Keyword.get(settings, &1))
      |> Enum.split_with(&is_nil/1)

    case values do
      [client_id, client_secret, tenant] ->
        {:service_principal, client_id, client_secret, tenant}

      _ ->
        nil
    end
  end

  defp try_service_principal(value, _settings), do: value

  defp try_managed_identity(nil, settings) do
    {missing_values, values} =
      [:storage_client_id, :storage_tenant_id, :storage_identity_token]
      |> Enum.map(&Keyword.get(settings, &1))
      |> Enum.split_with(&is_nil/1)

    case values do
      [client_id, tenant, identity_token] ->
        {:managed_identity, client_id, tenant, identity_token}

      [] ->
        nil

      _ ->
        raise "Azurex.Blob.Config: Missing values for managed identity #{Enum.join(missing_values, ", ")}"
    end
  end

  defp try_managed_identity(value, _settings), do: value

  @doc """
  Azure storage account connection string.
  Required if `storage_account_name` or `storage_account_key` not set.
  """
  @spec storage_account_connection_string(keyword) :: String.t() | nil
  def storage_account_connection_string(connection_params \\ []) do
    Keyword.get(connection_params, :storage_account_connection_string) ||
      Keyword.get(conf(), :storage_account_connection_string)
  end

  @spec parse_connection_string(nil | binary) :: map
  @doc """
  Parses a connection string to a key value map.

  ## Examples

      iex> parse_connection_string("Key=value")
      %{"Key" => "value"}

      iex> parse_connection_string("Key=value;")
      %{"Key" => "value"}

      iex> parse_connection_string("Key1=hello;Key2=world")
      %{"Key1" => "hello", "Key2" => "world"}

      iex> parse_connection_string(nil)
      %{}
  """
  def parse_connection_string(nil), do: %{}

  def parse_connection_string(connection_string) do
    connection_string
    |> String.split(";", trim: true)
    |> Enum.map(&String.split(&1, "=", parts: 2))
    |> Map.new(fn [key, value] -> {key, value} end)
  end

  @doc """
  Returns the value in the connection string given the string key.
  """
  @spec get_connection_string_value(String.t(), keyword) :: String.t() | nil
  def get_connection_string_value(key, connection_params \\ []) do
    storage_account_connection_string(connection_params)
    |> parse_connection_string()
    |> Map.get(key)
  end

  @doc """
  Returns the given configuration keyword list.
  If the parameter is a string, it is interpreted as the container for backwards compatibility.
  """
  @spec get_connection_params(config_overrides | nil) :: keyword()
  def get_connection_params(nil), do: []
  def get_connection_params(container) when is_binary(container), do: [container: container]
  def get_connection_params(config), do: config

  def get_auth_url do
    Keyword.get(conf(), :auth_url) || "https://login.microsoftonline.com"
  end

  # Reads a key from the connection string in the given settings only, so that
  # connection params are looked up before the application config.
  @spec connection_string_value(keyword, String.t()) :: String.t() | nil
  defp connection_string_value(settings, key) do
    settings
    |> Keyword.get(:storage_account_connection_string)
    |> parse_connection_string()
    |> Map.get(key)
  end
end

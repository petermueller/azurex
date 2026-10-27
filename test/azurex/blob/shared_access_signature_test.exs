defmodule Azurex.Blob.SharedAccessSignatureTest do
  use ExUnit.Case

  import Azurex.Blob.SharedAccessSignature
  import Azurex.ManagedIdentityHelpers

  @container "my_container"
  @blob "/folder/blob.mp4"
  @now ~U[2022-10-10 10:10:00Z]

  describe "account key configuration" do
    setup do
      Application.put_env(:azurex, Azurex.Blob.Config,
        storage_account_name: "storage_account",
        storage_account_key: Base.encode64("secretkey")
      )
    end

    test "sas container url" do
      assert sas_url(@container, "/", from: @now) ==
               "https://storage_account.blob.core.windows.net/my_container?sv=2020-12-06&st=2022-10-10T10%3A10%3A00Z&se=2022-10-10T11%3A10%3A00Z&sr=c&sp=r&sig=NRjiSKbIhZPcu99pYt2bS015eQOMTX8WVIh3hJdj%2Fwk%3D"
    end

    test "sas blob url" do
      assert sas_url(@container, @blob,
               from: @now,
               expiry: {:second, 2 * 24 * 3600},
               permissions: [:read, :write]
             ) ==
               "https://storage_account.blob.core.windows.net/my_container/folder/blob.mp4?sv=2020-12-06&st=2022-10-10T10%3A10%3A00Z&se=2022-10-12T10%3A10%3A00Z&sr=c&sp=rw&sig=Y2vH1nKzPkQhMnEXzz1m9Bz3o%2FPhyS1nOQp91B5GK9k%3D"
    end

    test "permissions order does not matter" do
      assert sas_url(@container, @blob,
               from: @now,
               permissions: [:read, :add, :write, :delete]
             ) ==
               sas_url(@container, @blob,
                 from: @now,
                 permissions: [:delete, :write, :add, :read]
               )
    end

    test "defaults to parameters from overrides" do
      url_with_env = sas_url(@container, @blob, from: @now)

      connection_params = Keyword.put(delete_env(), :container, @container)
      url_with_overrides = sas_url(connection_params, @blob, from: @now)

      assert url_with_env == url_with_overrides
    end

    test "without overrides, operates on default container" do
      env =
        Application.get_env(:azurex, Azurex.Blob.Config)
        |> Keyword.put(:default_container, @container)

      # Reapply environment but with default container
      Application.put_env(:azurex, Azurex.Blob.Config, env)

      assert sas_url([], "/", from: @now) == sas_url(@container, "/", from: @now)
    end
  end

  describe "managed identity configuration" do
    setup do
      bypass = Bypass.open()

      tenant_id = "tenant_id"

      Application.put_env(:azurex, Azurex.Blob.Config,
        api_url: "http://localhost:#{bypass.port}",
        auth_url: "http://localhost:#{bypass.port}",
        storage_account_name: "storage_account",
        storage_client_id: "storage_client_id",
        storage_tenant_id: tenant_id,
        storage_identity_token: create_token_file()
      )

      stub_get_bearer_token_request(bypass, tenant_id)
      stub_get_user_delegation_request(bypass)

      {:ok, bypass: bypass}
    end

    test "sas container url", %{bypass: bypass} do
      assert sas_url(@container, "/", from: @now) ==
               "http://localhost:#{bypass.port}/my_container?sv=2020-12-06&st=2022-10-10T10%3A10%3A00Z&se=2022-10-10T11%3A10%3A00Z&sr=c&sp=r&skoid=SignedOid&sktid=SignedTid&skt=SignedStart&ske=SignedExpiry&sks=SignedService&skv=SignedVersion&sig=MY5EFnYpuPi08LqVbu04IPgz8iHN6t8UlDNdt6Cqh1w%3D"
    end

    test "sas blob url", %{bypass: bypass} do
      assert sas_url(@container, @blob,
               from: @now,
               expiry: {:second, 2 * 24 * 3600},
               permissions: [:read, :write]
             ) ==
               "http://localhost:#{bypass.port}/my_container/folder/blob.mp4?sv=2020-12-06&st=2022-10-10T10%3A10%3A00Z&se=2022-10-12T10%3A10%3A00Z&sr=c&sp=rw&skoid=SignedOid&sktid=SignedTid&skt=SignedStart&ske=SignedExpiry&sks=SignedService&skv=SignedVersion&sig=Kl2qu2MajyMpuSBPlx4MiC2b7Jggo7PU75DTXvSE7jQ%3D"
    end

    test "permissions order does not matter" do
      assert sas_url(@container, @blob,
               from: @now,
               permissions: [:read, :add, :write, :delete]
             ) ==
               sas_url(@container, @blob,
                 from: @now,
                 permissions: [:delete, :write, :add, :read]
               )
    end

    test "defaults to parameters from overrides" do
      url_with_env = sas_url(@container, @blob, from: @now)

      # The token endpoint is still read from the application config
      env = Application.get_env(:azurex, Azurex.Blob.Config)
      Application.put_env(:azurex, Azurex.Blob.Config, Keyword.take(env, [:auth_url]))

      connection_params = Keyword.put(env, :container, @container)
      url_with_overrides = sas_url(connection_params, @blob, from: @now)

      assert url_with_env == url_with_overrides
    end
  end

  defp delete_env do
    env = Application.get_env(:azurex, Azurex.Blob.Config)
    container = env[:default_container]
    Application.put_env(:azurex, Azurex.Blob.Config, [])

    env
    |> Keyword.put(:container, container)
  end

  defp stub_get_bearer_token_request(bypass, tenant_id) do
    Bypass.stub(bypass, "POST", "/#{tenant_id}/oauth2/v2.0/token", fn conn ->
      token_response =
        %{access_token: "access_token", expires_in: 100} |> Jason.encode!()

      Plug.Conn.resp(conn, 200, token_response)
    end)
  end

  defp stub_get_user_delegation_request(bypass) do
    Bypass.stub(bypass, "POST", "/", fn %Plug.Conn{
                                          params: %{
                                            "comp" => "userdelegationkey",
                                            "restype" => "service"
                                          }
                                        } = conn ->
      xml = """
      <?xml version="1.0" encoding="utf-8"?>
      <UserDelegationKey>
      <SignedOid>SignedOid</SignedOid>
      <SignedTid>SignedTid</SignedTid>
      <SignedStart>SignedStart</SignedStart>
      <SignedExpiry>SignedExpiry</SignedExpiry>
      <SignedService>SignedService</SignedService>
      <SignedVersion>SignedVersion</SignedVersion>
      <Value>#{Base.encode64("Value")}</Value>
      </UserDelegationKey>
      """

      Plug.Conn.resp(conn, 200, xml)
    end)
  end
end

defmodule Azurex.Blob.SharedAccessSignature.UserDelegationSAS do
  @doc """
  Implements Service based User Delegation Shared Access Signature urls

  Based on:
  https://learn.microsoft.com/en-us/rest/api/storageservices/create-user-delegation-sas
  """
  alias Azurex.Authorization.Auth
  alias Azurex.Blob.Config

  import Azurex.Blob.SharedAccessSignature.Shared

  import SweetXml

  def build_token(
        resource_type,
        resource,
        {from, expiry},
        permissions,
        storage_account_name,
        connection_params \\ []
      ) do
    {:ok, user_delegation_key} = get_user_delegation_key(from, expiry, connection_params)

    URI.encode_query(
      sv: sv(),
      st: st(from),
      se: se(from, expiry),
      sr: sr(resource_type),
      sp: sp(permissions),
      skoid: skoid(user_delegation_key),
      sktid: sktid(user_delegation_key),
      skt: skt(user_delegation_key),
      ske: ske(user_delegation_key),
      sks: sks(user_delegation_key),
      skv: skv(user_delegation_key),
      sig:
        signature(
          resource_type,
          resource,
          {from, expiry},
          permissions,
          storage_account_name,
          user_delegation_key
        )
    )
  end

  defp get_user_delegation_key(from, expiry, connection_params) do
    %HTTPoison.Request{
      method: :post,
      url: Config.api_url(connection_params) <> "/",
      body: create_user_delegation_request_body(from, expiry),
      params: [restype: "service", comp: "userdelegationkey"]
    }
    |> Auth.authorize_request("", connection_params)
    |> HTTPoison.request()
    |> case do
      {:ok, %{body: xml, status_code: 200}} -> {:ok, xml}
      _ -> raise "Unable to obtain user delegation key"
    end
  end

  defp create_user_delegation_request_body(from, expiry) do
    """
    <?xml version="1.0" encoding="utf-8"?>
      <KeyInfo>
          <Start>#{st(from)}</Start>
          <Expiry>#{se(from, expiry)}</Expiry>
      </KeyInfo>
    """
  end

  defp signature(
         resource_type,
         resource,
         {from, expiry},
         permissions,
         storage_account_name,
         user_delegation_key
       ) do
    signature =
      Enum.join(
        [
          sp(permissions),
          st(from),
          se(from, expiry),
          canonicalized_resource(resource, storage_account_name),
          skoid(user_delegation_key),
          sktid(user_delegation_key),
          skt(user_delegation_key),
          ske(user_delegation_key),
          sks(user_delegation_key),
          skv(user_delegation_key),
          "",
          "",
          "",
          "",
          "",
          sv(),
          sr(resource_type),
          "",
          "",
          "",
          "",
          "",
          "",
          ""
        ],
        "\n"
      )

    key = user_delegation_key |> get_xml_value("Value") |> Base.decode64!()
    :crypto.mac(:hmac, :sha256, key, signature) |> Base.encode64()
  end

  # For User Delegation SAS keys
  defp skoid(user_delegation_key), do: get_xml_value(user_delegation_key, "SignedOid")
  defp sktid(user_delegation_key), do: get_xml_value(user_delegation_key, "SignedTid")
  defp skt(user_delegation_key), do: get_xml_value(user_delegation_key, "SignedStart")
  defp ske(user_delegation_key), do: get_xml_value(user_delegation_key, "SignedExpiry")
  defp sks(user_delegation_key), do: get_xml_value(user_delegation_key, "SignedService")
  defp skv(user_delegation_key), do: get_xml_value(user_delegation_key, "SignedVersion")

  defp get_xml_value(xml, key) do
    xml |> xpath(~x"/UserDelegationKey/#{key}/text()") |> to_string()
  end
end

defmodule Quarto.Cursor.Base64 do
  @moduledoc """
  Default cursor encoder/decoder

  Encodes a list of cursor values to a signed, url-safe string and vice-versa.

  Cursors come back from clients, so they are signed with
  `Plug.Crypto.MessageVerifier` and the signature is verified before the
  payload is deserialized. A cursor that wasn't issued by this application
  (forged, tampered with, or signed with another secret) is rejected without
  ever reaching `:erlang.binary_to_term/2`.

  ## Configuration

  A secret of at least 32 bytes is required:

      config :quarto, cursor_secret: System.fetch_env!("QUARTO_CURSOR_SECRET")

  Changing the secret invalidates every cursor already issued.
  """
  alias Plug.Crypto.KeyGenerator
  alias Plug.Crypto.MessageVerifier
  alias Quarto.Cursor
  @behaviour Quarto.Cursor

  @salt "quarto cursor"
  # Base64 of "HS256", the MessageVerifier header for :sha256
  @header "SFMyNTY."
  @min_secret_size 32

  @impl true
  def decode(cursor, opts \\ [])
  def decode(nil, _opts), do: {:ok, nil}

  def decode(encoded_cursor, _opts) when is_binary(encoded_cursor) do
    with {:ok, binary} <- verify(encoded_cursor),
         {:ok, values} <- safe_binary_to_term(binary) do
      {:ok, Enum.map(values, &Cursor.Decode.convert/1)}
    end
  end

  def decode(_encoded_cursor, _opts), do: {:error, :invalid_cursor}

  @impl true
  def decode!(encoded_cursor, opts \\ []) do
    case decode(encoded_cursor, opts) do
      {:ok, cursor} -> cursor
      {:error, error} -> raise(ArgumentError, "error decoding cursor (#{error})")
    end
  end

  @impl true
  def encode(values, opts \\ [])

  def encode(values, _opts) when is_list(values) do
    result =
      values
      |> Enum.map(&Cursor.Encode.convert/1)
      |> :erlang.term_to_binary()
      |> sign()

    {:ok, result}
  end

  def encode(value, _opts) do
    encode([value])
  end

  @impl true
  def encode!(values, opts \\ []) do
    {:ok, cursor} = encode(values, opts)
    cursor
  end

  # MessageVerifier tokens are "<header>.<payload>.<signature>", we strip the header before giving it to the client as its not needed.
  defp sign(binary) do
    @header <> cursor = MessageVerifier.sign(binary, signing_key(), :sha256)
    cursor
  end

  defp verify(encoded_cursor) do
    case MessageVerifier.verify(@header <> encoded_cursor, signing_key()) do
      {:ok, binary} -> {:ok, binary}
      :error -> {:error, :invalid_signature}
    end
  end

  defp safe_binary_to_term(binary) do
    case Plug.Crypto.non_executable_binary_to_term(binary, [:safe]) do
      values when is_list(values) -> {:ok, values}
      _other -> {:error, :invalid_cursor}
    end
  rescue
    ArgumentError -> {:error, :invalid_cursor}
  end

  defp signing_key do
    KeyGenerator.generate(secret(), @salt, cache: Plug.Crypto.Keys)
  end

  defp secret do
    case Application.get_env(:quarto, :cursor_secret) do
      secret when is_binary(secret) and byte_size(secret) >= @min_secret_size ->
        secret

      _ ->
        raise ArgumentError,
              "config :quarto, :cursor_secret must be set to a binary of at least " <>
                "#{@min_secret_size} bytes to sign pagination cursors"
    end
  end
end

defmodule Quarto.Cursor.Base64Test do
  # async: false because one test temporarily changes the :quarto app env
  use ExUnit.Case, async: false

  alias Quarto.Cursor

  defmodule MYTEST1 do
    defstruct id: nil
  end

  defmodule MYTEST2 do
    defstruct id: nil
  end

  defimpl Quarto.Cursor.Encode, for: MYTEST1 do
    def convert(term), do: {:m1, term.id}
  end

  defimpl Quarto.Cursor.Decode, for: Tuple do
    def convert({:m1, id}), do: %MYTEST1{id: id}
  end

  defp unsigned(term), do: term |> :erlang.term_to_binary() |> Base.url_encode64()

  defp signing_key do
    Plug.Crypto.KeyGenerator.generate(
      Application.fetch_env!(:quarto, :cursor_secret),
      "quarto cursor"
    )
  end

  # Signs a raw binary the same way Quarto.Cursor.Base64 does, so tests can
  # build validly signed cursors with payloads encode/1 would never produce.
  defp signed(binary) do
    "SFMyNTY." <> cursor = Plug.Crypto.MessageVerifier.sign(binary, signing_key(), :sha256)
    cursor
  end

  describe "encoding and decoding terms" do
    test "cursor for struct with custom implementation is shorter" do
      cursor1 = Cursor.Base64.encode!([%MYTEST1{id: 1}])

      assert Cursor.Base64.decode!(cursor1) == [%MYTEST1{id: 1}]

      cursor2 = Cursor.Base64.encode!([%MYTEST2{id: 1}])

      assert Cursor.Base64.decode!(cursor2) == [%MYTEST2{id: 1}]
      assert bit_size(cursor1) < bit_size(cursor2)
    end

    test "struct values round-trip" do
      values = [
        ~U[2026-11-24 12:34:56.123456Z],
        ~N[2026-11-24 12:34:56.789],
        ~D[2026-11-24],
        Decimal.new("10.50"),
        123,
        "abc",
        true,
        nil
      ]

      assert Cursor.Base64.decode!(Cursor.Base64.encode!(values)) == values
    end

    test "it wraps terms into lists" do
      cursor = Cursor.Base64.encode!(1)

      assert Cursor.Base64.decode!(cursor) == [1]
    end

    test "it doesn't wrap a list in a list" do
      cursor = Cursor.Base64.encode!([1])

      assert Cursor.Base64.decode!(cursor) == [1]
      refute Cursor.Base64.decode!(cursor) == [[1]]
    end

    test "the cursor is url safe" do
      cursor = Cursor.Base64.encode!([~U[2026-11-24 12:34:56Z], "a/b+c", 123])

      assert cursor == URI.encode_www_form(cursor)
    end
  end

  describe "Cursor.Base64.decode/1" do
    test "it safely decodes user input" do
      assert_raise ArgumentError, fn ->
        # this binary represents the atom :fubar_0a1b2c3d4e
        <<131, 100, 0, 16, "fubar_0a1b2c3d4e">>
        |> signed()
        |> Cursor.Base64.decode!()
      end
    end

    test "it returns error for bogus cursor" do
      assert {:error, :invalid_signature} == Cursor.Base64.decode("❌")
    end

    test "it raises error for bogus cursor" do
      assert_raise ArgumentError, fn -> Cursor.Base64.decode!("❌") end
    end

    test "it refuses unsigned cursors" do
      struct = %{__struct__: URI, host: "example.com"}

      for term <- [[1], [~U[2026-11-24 12:34:56Z]], struct, [struct], [{:ok, struct}]] do
        assert {:error, :invalid_signature} == Cursor.Base64.decode(unsigned(term))
      end
    end

    test "the cursor is <payload>.<signature> without the digest header" do
      payload = Base.url_encode64(:erlang.term_to_binary([1]), padding: false)

      assert [^payload, _signature] = String.split(Cursor.Base64.encode!([1]), ".")
    end

    test "it refuses tampered cursors" do
      [payload, signature] = String.split(Cursor.Base64.encode!([1]), ".")
      forged_payload = Base.url_encode64(:erlang.term_to_binary([2]), padding: false)

      assert {:error, :invalid_signature} ==
               Cursor.Base64.decode(Enum.join([forged_payload, signature], "."))

      assert {:error, :invalid_signature} ==
               Cursor.Base64.decode(Enum.join([payload, "AAAA"], "."))
    end

    test "the client can't choose the digest" do
      binary = :erlang.term_to_binary([1])

      for digest <- [:sha256, :sha384, :sha512] do
        full_token = Plug.Crypto.MessageVerifier.sign(binary, signing_key(), digest)

        assert {:error, :invalid_signature} == Cursor.Base64.decode(full_token)
      end
    end

    test "it refuses cursors signed with a different secret" do
      cursor = Cursor.Base64.encode!([1])
      original = Application.fetch_env!(:quarto, :cursor_secret)

      try do
        Application.put_env(:quarto, :cursor_secret, String.duplicate("x", 64))
        assert {:error, :invalid_signature} == Cursor.Base64.decode(cursor)
      after
        Application.put_env(:quarto, :cursor_secret, original)
      end
    end

    test "it refuses signed terms that aren't a list" do
      for term <- [1, "abc", {:a, :b}, %{"a" => 1}] do
        cursor = term |> :erlang.term_to_binary() |> signed()

        assert {:error, :invalid_cursor} == Cursor.Base64.decode(cursor)
      end
    end

    test "it refuses non-binary cursors" do
      assert {:error, :invalid_cursor} == Cursor.Base64.decode(123)
    end
  end

  describe "configuration" do
    test "it raises when the secret is missing or too short" do
      original = Application.fetch_env!(:quarto, :cursor_secret)

      try do
        for secret <- [nil, "too short"] do
          Application.put_env(:quarto, :cursor_secret, secret)

          assert_raise ArgumentError, ~r/cursor_secret must be set/, fn ->
            Cursor.Base64.encode!([1])
          end
        end
      after
        Application.put_env(:quarto, :cursor_secret, original)
      end
    end
  end
end

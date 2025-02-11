defmodule QuickSnmp do
  @moduledoc """
  For using on a module just add:
    use QuickSnmp

  Functions availables:
    - get/5
    - get2/5
    - get/1
    - set/5
    - set2/5
    - set/1
    - getnext/5
    - getnext2/5
    - getnext/1
    - walk/5
    - walk2/5
    - walk/1
    - settings

  This library support only version 1 and 2 of SNMP protocol.

  """
  
  use Application
  
  alias Log
  alias SNMP, as: SNMP_EX

  defmodule Req do
    @enforce_keys [:host, :community, :oids]
    defstruct [
      :host,
      :community,
      :oids,
      type: :get, # ignored on walk
      port: 161,
      timeout: 2500,
      version: :v1,
      max_repetitions: 2,
      take: :all # just for walk
    ]
  end

  defmacro __using__(options \\ []) do
    quote do
      alias QuickSnmp, as: QSNMP
      Process.put(:numeric_return, false)
      unquote(options) |> Enum.each( fn {k, v} -> QuickSnmp.settings(k, v) end)
      true
    end
  end

  def start(_) do
      if (:ets.whereis(:snmp_mibs) == :undefined) do
        case :ets.file2tab(:code.priv_dir(:quick_snmp_ex) ++ ~c"/mibs2elixir.ets") do
          {:error, :cannot_create_table } -> {:ok, :snmp_mibs }
          {:error, _} ->
            Log.log(:warning, "[SNMP]: File 'priv/mibs2elixir.ets' does not exists")
            try do
              QuickSnmp.csv2ets(List.to_string(:code.priv_dir(:quick_snmp_ex)) ++ "priv/mibs2elixir.csv")
              :ets.file2tab(:code.priv_dir(:quick_snmp_ex) ++ ~c"priv/mibs2elixir.ets")
            rescue
              e -> raise("[SNMP]: File 'priv/mibs2elixir.csv' does not exists")
            end
          result ->
            result
        end
      end 
  end

  ###########################################################################
  ## Module API

  # get/5 wrap get/1
  def get(host, community, oids, timeout \\ 2500, max_repetitions \\ 2), do:
    get(%Req{host: host, community: community, oids: oids, timeout: timeout, max_repetitions: max_repetitions})

  # get2/5 wrap get/1
  def get2(host, community, oids, timeout \\ 2500, max_repetitions \\ 2), do:
    get(%Req{host: host, community: community, oids: oids, version: :v2, timeout: timeout, max_repetitions: max_repetitions})

  # get/1
  def get(%Req{max_repetitions: max_repetitions}) when max_repetitions == 0, do: :timeout
  def get(%Req{oids: oids} = request) when not is_list(oids), do:
    get(%{request | oids: [oids]})

  ###############
  ### get/1 - MAIN
  def get(%Req{host: host, community: community, oids: oids} = request) do
    uri = URI.parse("snmp://#{host}:#{request.port}")
    credential = SNMP_EX.credential(%{version: request.version, community: community})
    varbinds = oids |> Enum.reduce([], fn (oid, var) ->
      parsed_oid = parse_oid(oid)
      [ %{oid: parsed_oid, type: request.type || :get} ] ++ var
    end)

    case SNMP_EX.request(%{uri: uri, credential: credential, varbinds: varbinds}, [timeout: request.timeout]) do
      {:error, :etimedout } ->
        get(%Req{request | max_repetitions: request.max_repetitions - 1})
      {:error, _ } ->
        nil
      {:ok, result } when length(result) == 1 and request.type == :get ->
        [%{oid: _, value: value}] = result
        value
      {:ok, result } ->
        result |> Enum.reduce(%{}, fn (res, acc) ->
          %{oid: oid, value: value} = res
          if settings(:numeric_return) do
              Map.put(acc, oid, value)
          else
              Map.put(acc, list_oid_to_string(oid), value)
          end
        end)
      respose ->
        Log.log(:warning, "[SNMP]: Unknown response to request: #{inspect(respose)}")
        nil
      end
  end
  # get/1 - error
  def get(prms), do:
    Log.log(:error, "[SNMP]: SNMP Request missing mandatory pararemeter: #{inspect(prms)}")


  ###########################################################################3
  # set/5 wrap set/1
  def set(host, community, oids, timeout \\ 2500, max_repetitions \\ 2), do:
    set(%Req{host: host, community: community, oids: oids, timeout: timeout, max_repetitions: max_repetitions})

  # set2/5 wrap set2/1
  def set2(host, community, oids, timeout \\ 2500, max_repetitions \\ 2), do:
    set(%Req{host: host, community: community, oids: oids, version: :v2, timeout: timeout, max_repetitions: max_repetitions})

  # set/1
  def set(%Req{max_repetitions: max_repetitions}) when max_repetitions == 0, do: :timeout
  def set(%Req{oids: oids} = request) when not is_list(oids), do:
    set(%{request | oids: [oids]})

  ###############
  ### set/1 - MAIN
  def set(%Req{host: host, community: community, oids: oids} = request) do
    uri = URI.parse("snmp://#{host}:#{request.port}")
    credential = SNMP_EX.credential(%{version: request.version, community: community})
    varbinds = oids |> Enum.reduce([], fn (%{oid: oid, type: type, value: value}, var) ->
      parsed_oid = parse_oid(oid)
      [ %{oid: parsed_oid, type: type, value: value} | var ]
    end)

    case SNMP_EX.request(%{uri: uri, credential: credential, varbinds: varbinds}, [timeout: request.timeout]) do
      {:error, :etimedout } ->
        set(%Req{request | max_repetitions: request.max_repetitions - 1})
      {:error, _ } ->
        nil
      {:ok, result } when length(result) == 1 and request.type == :set ->
        [%{oid: _, value: value}] = result
        value
      {:ok, result } ->
        result |> Enum.reduce(%{}, fn (res, acc) ->
          %{oid: oid, value: value} = res
          if settings(:numeric_return) do
              Map.put(acc, oid, value)
          else
              Map.put(acc, list_oid_to_string(oid), value)
          end
        end)
      respose ->
        Log.log(:warning, "[SNMP]: Unknown response to request: #{inspect(respose)}")
        nil
      end
  end
  # set/1 - error
  def set(prms), do:
    Log.log(:error, "[SNMP]: SNMP Request missing mandatory pararemeter: #{inspect(prms)}")

  ###########################################################################3
  # getnext2/5 wrap get/1
  def getnext2(host, community, oids, timeout \\ 2500, max_repetitions \\ 2), do:
    get(%Req{host: host, community: community, oids: oids, type: :next, version: :v2, timeout: timeout, max_repetitions: max_repetitions})

  # getnext/5 wrap get/1
  def getnext(host, community, oids, timeout \\ 2500, max_repetitions \\ 2), do:
    get(%Req{host: host, community: community, oids: oids, type: :next, timeout: timeout, max_repetitions: max_repetitions})

  # getnext/1
  def getnext(request), do:
    get(%{request | type: :next})


  ###########################################################################3
  # walk2/5
  def walk2(host, community, oids, timeout \\ 2500, max_repetitions \\ 2), do:
    walk(%Req{host: host, community: community, oids: oids, type: :next, version: :v2, timeout: timeout, max_repetitions: max_repetitions})
  # walk/5
  def walk(host, community, oids, timeout \\ 2500, max_repetitions \\ 2), do:
    walk(%Req{host: host, community: community, oids: oids, type: :next, timeout: timeout, max_repetitions: max_repetitions})

  # walk/1
  def walk(%Req{oids: oids} = request) when not is_list(oids), do:
    walk(%{request | oids: [oids]})
  def walk(%Req{host: host, community: community, oids: oids} = request) do
    uri = URI.parse("snmp://#{host}:#{request.port}")
    credential = SNMP_EX.credential(%{version: request.version, community: community})

    varbinds = oids |> Enum.reduce([], fn (oid, var) ->
      parsed_oid = parse_oid(oid)
      [ %{oid: parsed_oid, type: request.type || :get} ] ++ var
    end)

    stream = SNMP_EX.walk(%{uri: uri, credential: credential, varbinds: varbinds})
    walk_result =
      try do
        case request.take do
          :all -> Enum.to_list(stream)
          _ -> Enum.take(stream, request.take)
        end
      rescue
        _ -> []
      end

    case walk_result do
      [] -> nil
      result ->
        try do
          result |> Enum.reduce(%{}, fn (res, acc) ->
            %{oid: oid, value: value} = res
            if settings(:numeric_return) do
                Map.put(acc, oid, value)
            else
                Map.put(acc, list_oid_to_string(oid), value)
            end
          end)
        rescue
          _ -> :timeout
        end
    end
  end

  def version_to_atom(version) when is_integer(version), do: String.to_atom("v" <> Integer.to_string(version))
  def version_to_atom(version) when is_atom(version), do: version
  def version_to_atom(_), do: :v1

  ###########################################################################3
  # Accesories
  @doc """
  Function settings support next opts:
    - :numeric_return -> true | false
    - ...
  """
  def settings(key, value), do: Process.put(key, value)
  def settings(key), do: Process.get(key)



  ###########################################################################3
  ## Utils
  def csv2ets(file) do
    try do
      :ets.delete(:snmp_mibs)
    rescue
      _ -> :ok
    end
    table = :ets.new(:snmp_mibs, [:ordered_set, :named_table, :public, read_concurrency: true])
    file |> File.stream!() |> Stream.map(fn row ->
      [str_oid, num_str_oid] = row |> String.trim() |> String.split(";")
      num_list_oid = SNMP.string_oid_to_list(num_str_oid)
      {str_oid, num_list_oid}
    end) |> Enum.map(fn record ->
      :ets.insert(table, record)
      :ets.insert(table, record |> Tuple.to_list() |> :lists.reverse() |> List.to_tuple())
    end)

    :ets.tab2file(table, file |> String.replace(".csv", ".ets") |> String.to_charlist())
    :ets.delete(table)
  end

  def string_oid_to_list(oid) do
    [ oid1 |  oid2 ] = String.split(oid, "::")
    oid =
        if oid2 == [] do
            oid1
        else
            Enum.at(oid2, 0)
        end
    [ oid |  rest ] = String.split(oid, ".")
    case :ets.lookup(:snmp_mibs, oid) do
      [] ->
        Log.log(:error, "[SNMP]: Oid '#{oid}' does not exists!")
        false
      [{_, noid}] ->
        noid ++ Enum.map(rest, fn s -> String.to_integer(s) end)
    end
  end

  ###########################################################################3
  ## Private Tools
  defp parse_oid(oid) when is_list(oid), do: oid
  defp parse_oid(oid) when is_bitstring(oid) do
    cond do
      oid =~ ~r/^(\.|)[0-9]+(\.[0-9]+)*(\.|)$/ -> SNMP_EX.string_oid_to_list(oid)

      oid =~ ~r/^[a-zA-Z][a-zA-Z0-9]+\.[0-9]+(\.[0-9]+)*$/ ->
        [_, str, num] = Regex.run(~r/^([a-zA-Z][a-zA-Z0-9]+)\.([0-9]+(?:\.[0-9]+)*)$/, oid)
        string_oid_to_list(str) ++ (num |> String.split(".") |> Enum.map(fn n -> String.to_integer(n) end))

      true -> string_oid_to_list(oid)
    end
  end

  defp list_oid_to_string(oid, tail \\ [])
  defp list_oid_to_string([], tail), do: tail
  defp list_oid_to_string(oid, tail ) do
    case :ets.lookup(:snmp_mibs, oid) do
      [] ->
        list_oid_to_string(:lists.droplast(oid), [ :lists.last(oid) | tail ] )
      [{_, soid}] ->
        soid <> "." <> Enum.join(tail, ".")
    end
  end

end

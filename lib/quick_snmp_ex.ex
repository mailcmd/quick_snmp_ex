defmodule QuickSnmp do
  @moduledoc """
  Para utilizar el módulo:
    use QuickSnmp

  Funciones disponibles:
    - get
    - getnext
    - walk
    - settings

  """
  use Abn.Lib

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

  defmacro __using__(_) do
    quote do
      alias QuickSnmp
      if (:ets.whereis(:snmp_mibs) == :undefined) do

        case :ets.file2tab(~c"./lib/mibs/mibs2elixir.ets") do
          {:error, :cannot_create_table } -> {:ok, :snmp_mibs }
          {:error, _} ->
            Log.log(:warning, "[SNMP]: File 'lib/mibs/mibs2elixir.ets' does not exists")
            try do
              QuickSnmp.csv2ets("./lib/mibs/mibs2elixir.csv")
              :ets.file2tab(~c"./lib/mibs/mibs2elixir.ets")
            rescue
              e -> raise("[SNMP]: File 'lib/mibs/mibs2elixir.csv' does not exists")
            end
          result ->
            result
        end

      end
      Process.put(:numeric_return, false)
      true
    end
  end

  ###########################################################################
  ## Module API

  # get2/5 wrap get/1
  def get2(host, community, oids, timeout \\ 2500, max_repetitions \\ 2), do:
    get(%Req{host: host, community: community, oids: oids, version: :v2, timeout: timeout, max_repetitions: max_repetitions})

  # get/5 wrap get/1
  def get(host, community, oids, timeout \\ 2500, max_repetitions \\ 2), do:
    get(%Req{host: host, community: community, oids: oids, timeout: timeout, max_repetitions: max_repetitions})

  # get/1
  def get(%Req{oids: oids} = request) when not is_list(oids), do:
    get(%{request | oids: [oids]})
  # get/1 - main
  def get(%Req{host: host, community: community, oids: oids} = request) do
    uri = URI.parse("snmp://#{host}:#{request.port}")
    credential = SNMP_EX.credential(%{version: request.version, community: community})
    varbinds = oids |> Enum.reduce([], fn (oid, var) ->
      parsed_oid = parse_oid(oid)
      [ %{oid: parsed_oid, type: request.type || :get} ] ++ var
    end)

    case SNMP_EX.request(%{uri: uri, credential: credential, varbinds: varbinds}) do
      {:error, :etimedout } -> :timeout
      {:error, _ } -> nil
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
            Enum.at(oid2, 0))
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

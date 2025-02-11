defmodule QuickSnmpEx.MixProject do
  use Mix.Project

  def project do
    [
      app: :quick_snmp_ex,
      version: "0.1.0",
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :quick_snmp_ex ]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
      { :snmp_ex, git: "https://github.com/mailcmd/snmp-elixir.git" },
      { :log_ex, git: "https://github.com/mailcmd/log_ex.git"}
    ]
  end
end

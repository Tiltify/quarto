import Config

config :logger, level: :info

config :quarto, cursor_secret: "quarto-test-cursor-secret-0123456789abcdef"

config :stream_data,
  max_runs: if(System.get_env("CI"), do: 200, else: 50)

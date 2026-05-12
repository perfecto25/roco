class Logger
  enum Level
    Debug = 0
    Info  = 1
    Warn  = 2
    Error = 3
  end

  @@level : Level = Level::Info
  @@output : IO = STDOUT
  @@mutex = Mutex.new

  def self.configure(destination : String, level_name : String) : Void
    @@level = parse_level(level_name)

    if destination == "stdout" || destination.empty?
      @@output = STDOUT
    else
      begin
        @@output = File.open(destination, "a")
      rescue ex
        STDERR.puts "[logger] Could not open #{destination}: #{ex.message}. Falling back to stdout."
        @@output = STDOUT
      end
    end
  end

  def self.debug(component : String, message : String) : Void
    write(Level::Debug, component, message)
  end

  def self.info(component : String, message : String) : Void
    write(Level::Info, component, message)
  end

  def self.warn(component : String, message : String) : Void
    write(Level::Warn, component, message)
  end

  def self.error(component : String, message : String) : Void
    write(Level::Error, component, message)
  end

  private def self.write(level : Level, component : String, message : String) : Void
    return if level.value < @@level.value
    timestamp = Time.utc.to_s("%Y-%m-%dT%H:%M:%S")
    line = "#{timestamp} #{level.to_s.upcase.ljust(5)} [roco] #{component}: #{message}"
    @@mutex.synchronize do
      @@output.puts line
      @@output.flush
    end
  end

  private def self.parse_level(s : String) : Level
    case s.downcase
    when "debug" then Level::Debug
    when "info"  then Level::Info
    when "warn"  then Level::Warn
    when "error" then Level::Error
    else Level::Info
    end
  end
end

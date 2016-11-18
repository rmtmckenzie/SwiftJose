Pod::Spec.new do |spec|
  spec.name = "SwiftJose"
  spec.version = "0.0.1"
  spec.summary = "Framework to create and parse JWT, JWS, and JWE"
  spec.homepage = "https://github.com/rmtmckenzie/SwiftJose"
  spec.license = { type: 'MIT', file:'LICENSE' }
  spec.authors = { "Morgan McKenzie" => 'rmtmckenzie@gmail.com' }

  spec.platform = :ios, "10.0"
  spec.requires_arc = true
  spec.source = { git: "https://github.com/rmtmckenzie/SwiftJose.git", tag: "v#{spec.version}", submodules: true }
  spec.source_files = "SwiftJose/**/*.{h, swift}"

  ## SwCrypt dependency??
end

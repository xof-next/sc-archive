# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name = 'sc-archive'
  spec.version = '1.0.0'
  spec.summary = 'Password-protected SCAR v2 archive utility'
  spec.description = 'Cross-runtime encrypted .sc archives with independent recovery credentials.'
  spec.authors = ['SC Archive contributors']
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 3.0'
  spec.files = Dir['sc.rb', 'lib/**/*.rb', 'README.md', 'Gemfile']
  spec.bindir = '.'
  spec.executables = ['sc.rb']
  spec.add_runtime_dependency 'rubyzip', '>= 3.2', '< 4.0'
end

Puppet::Parser::Functions.newfunction(:legacy_lookup, type: :rvalue) do |args|
  scope.compiler.catalog.add_resource(args.first)
end

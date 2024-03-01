class AccessPolicy < MongoidApplicationRecord
    
    field :name, type: String
    field :description, type: String

    # Whether to Allow or Deny access
    field :effect, type: String

    # Action performeable on the attached resources
    field :actions, type: Array

    # Principals(roles, groups, iams) to allow or deny access
    field :principals, type: Array

    # Resources managed by this policy
    field :resources, type: Array

    # Conditions for this policy
    # field :conditions, type: Array

    validates :name, presence: true, uniqueness: true
    validates :description, presence: true
    validates :effect, inclusion: { in: %w(Allow Deny), message: "'%{value}' is not a valid effect" }

    validate :check_actions
    validate :check_principals
    validate :check_resources
    # validate :check_conditions

    # def check_conditions

    # end

    def check_actions
        unless check_emptiness("actions", actions)
            return
        end

        action_pattern = /krn:action:.+:.+\z/

        actions.each do |action|
            unless validate_scheme("actions", action, action_pattern)
                break
            end

            unless entity_exists?("actions", action)
                break
            end
        end
    end

    def check_principals
        unless check_emptiness("principals", principals)
            return
        end

        principal_pattern = /\A(krn:(role|group|user|client)):.+:.+\z/

        principals.each do |principal|
            
            unless validate_scheme("principals", principal, principal_pattern)
                break
            end

            unless entity_exists?("principals", principal)
                break
            end
        end
    end

    def check_resources
        unless check_emptiness("resources", resources)
            return
        end

        resource_pattern = /krn:.+:.+:.+\z/

        resources.each do |resource|
            unless validate_scheme("resources", resource, resource_pattern)
                break
            end

            unless entity_exists?("resources", resource)
                break
            end
        end
    end

    def validate_scheme(fld, scheme, pattern) 
        unless scheme.count(":") == 3 and scheme.match(pattern)
            errors.add(fld.to_sym, "'#{scheme}' is an invalid KRN for #{fld}")
            return false
        end

        true
    end

    def check_emptiness(fld, fld_array)
        if fld_array.empty?
            errors.add(fld.to_sym, "At least one #{ActiveSupport::Inflector.singularize(fld)} is required")
            return false
        end
        true
    end

    def join_with_or(strings)
        if strings.length > 2
          last_element = strings.pop
          result = "#{strings.join(', ')} or #{last_element}"
        elsif strings.length == 2
          result = strings.join(' or ')
        else
          result = strings.join("")
        end
        result
      end

    def entity_exists?(flds, krn)

        _, resource_type, resource_field, resource_field_value = krn.split(':')

        exists = false

        resource_class = nil

        if resource_type == "*"
            # All resources
            return true
        elsif ["role", "group", "user", "client", "case", "action", "access_policy"].include?(resource_type)
            
            begin
                resource_class = Strings.snake_to_camel(resource_type).constantize
                
                if resource_field == "*" # All resources
                    return true
                end

                if resource_class.ancestors.include?(ApplicationRecord)
                    database_fields = resource_class.columns.map(&:name) # Extract attributes for resource

                    # Check resource attributes
                    unless database_fields.include?(resource_field)
                        errors.add(flds.to_sym, "Unknown attribute #{resource_field} for #{resource_class.to_s}")
                        return false
                    end

                    # Validate uuid
                    if resource_field == "id"
                        unless "#{resource_field_value}".match?(/[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}\z/)
                            errors.add(flds.to_sym, "'#{resource_field_value}' is not a valid uuid for the #{resource_field} field")
                            return false
                        end
                    end

                    # Check if record exists
                    unless resource_class.exists?(["#{resource_field} = ?", resource_field_value])
                        errors.add(flds.to_sym, "#{resource_class.to_s} by #{resource_field} '#{resource_field_value}' does not exist")
                        return false
                    end
                    exists = true
                elsif resource_class.ancestors.include?(MongoidApplicationRecord)
                    database_fields = resource_class.fields.keys # Extract attributes for resource

                    # Check resource attributes
                    unless database_fields.include?(resource_field)
                        errors.add(flds.to_sym, "Unknown attribute #{resource_field} for #{resource_class.to_s}")
                        return false
                    end

                    # Check if record exists
                    unless resource_class.exists?("#{resource_field}" => { "$eq" => resource_field_value })
                        errors.add(flds.to_sym, "#{resource_class.to_s} by #{resource_field} '#{resource_field_value}' does not exist")
                        return false
                    end
                    exists = true
                else
                    # Not a database resource
                end
            rescue => exception
                errors.add(flds.to_sym, "Unknown resource '#{resource_type}'")
                return false
            end
        else
            errors.add(flds.to_sym, "Invalid resource type, '#{resource_type}'")
            return false
        end
        exists
    end
end

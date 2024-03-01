# frozen_string_literal: true

class ApplicationPolicy
  attr_reader :user, :record

  def initialize(user, record)
    raise Pundit::NotAuthorizedError, "You are not logged in" unless user
    @user = user
    @record = record
  end

  def index?
    false
  end

  def show?
    false
  end

  def create?
    false
  end

  def new?
    create?
  end

  def update?
    false
  end

  def edit?
    update?
  end

  def destroy?
    false
  end

  def has_role?(role)
    @user.authorities.include?(role)
  end

  def resolve_access?(resource_type, desired_action)
    # Check for any access policy
    policies = AccessPolicy.where(
      :resources => {"$elemMatch" => {"$eq" => "krn:#{resource_type}:#{@record&.id}"}},
      :actions => {"$elemMatch" => {"$eq" => "krn:action:#{desired_action}"}}
    )
    
    # Immediately deny access if no policy is attached
    return false if (policies.nil? || policies.empty?)

    current_principals = [@user.authorities.map { |a| a.starts_with?("ROLE") ? Role.to_krn(a) : Group.to_krn(a)  } , "krn:#{@user.grant == "user" ? "user" : "client"}:#{@user.principal["id"]}", "krn:#{@user.grant}:#{@user.principal["username"]}"].flatten
    
    # Evaluate each policy
    policies.each do |policy|
      return false if deny_access?(policy, current_principals)
      return true if allow_access?(policy, current_principals)
    end
    
    # No policy resolved at all
    false
  end

  def deny_access?(policy, current_principals)
    current_principals.intersect?(policy.principals) && policy.effect == "Deny"
  end

  def allow_access?(policy, current_principals)
    current_principals.intersect?(policy.principals) && policy.effect == "Allow"
  end

  class Scope
    def initialize(user, scope)
      @user = user
      @scope = scope
    end

    def resolve
      raise NotImplementedError, "You must define #resolve in #{self.class}"
    end

    private

    attr_reader :user, :scope
  end
end

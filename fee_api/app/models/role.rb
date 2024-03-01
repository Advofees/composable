class Role < ApplicationRecord

    has_many :user_roles
    has_many :users, through: :user_roles
    
    has_many :role_groups
    has_many :groups, through: :role_groups

    before_save :uppercase_name

    def self.to_krn(role_name)
        "krn:role:name:#{role_name}"
    end

    private

    def uppercase_name
        self.name = ["ROLE", *name.upcase.split(/\s+/)].join("_")
    end
end

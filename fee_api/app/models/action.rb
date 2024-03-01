class Action < ApplicationRecord
    validates :name, uniqueness: true, presence: true

    validate :check_spaces

    private

    def check_spaces
        errors.add(:name, "can't contain spaces") if name.match?(/\s+/)
    end
end

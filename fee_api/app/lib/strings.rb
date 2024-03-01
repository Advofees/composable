class Strings

    def self.snake_to_camel(snake)
        "#{snake}".split('_').map { |token| token.camelcase }.join('')
    end
end
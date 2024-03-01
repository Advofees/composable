class MongoidApplicationRecord

    include Mongoid::Document
    include Mongoid::Timestamps

    field :id, as: :_id

end
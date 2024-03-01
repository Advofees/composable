class PoliciesController < ApplicationController
    skip_before_action :authenticate, only: [:index_of_access_policies, :show_access_policy, :create_access_policy, :index_of_resource_actions, :show_resource_action, :create_resource_action]

    def index_of_access_policies
        render json: AccessPolicy.all
    end

    def show_access_policy
        render json: AccessPolicy.find(params[:id])
    end

    def create_access_policy
        render json: AccessPolicy.create!(access_policy_params)
    end

    def index_of_resource_actions
        render json: Action.all
    end

    def show_resource_action
        render json: Action.find(params[:id])
    end

    def create_resource_action
        render json: Action.create!(resource_action_params)
    end

    private

    def access_policy_params
        params.permit(
            :name,
            :description,
            :effect,
            actions: [],
            principals: [],
            resources: []
        )
    end

    def resource_action_params
        params.permit(
            :name
        )
    end
end

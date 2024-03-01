class CasesController < ApplicationController
  before_action :set_case, only: [:payment_information, :create_payment_information, :add_party, :add_installment, :update, :payment_information, :update_network_payment_information, :case_documents, :hearings, :important_dates, :tasks, :parties, :destroy, :show]

  def count
    render json: { count: policy_scope(Case).count }
  end

  def search_count
    begin
      render json: { count: policy_scope(Case).where("cases.#{params[:q]}::text ILIKE ?", "%#{params[:v].strip}%").count }
    rescue ActiveRecord::StatementInvalid => e
      render json: { count: 0 }
    end
  end

  def search_cases
    begin
      render json: policy_scope(Case).where("cases.#{params[:q]}::text ILIKE ?", "%#{params[:v]}%").order("created_at DESC").paginate(page: params[:page_number], per_page: params[:page_population])
    rescue ActiveRecord::StatementInvalid => e
      render json: []
    end
  end

  def index
    render json: policy_scope(Case).order("created_at DESC").paginate(page: params[:page_number], per_page: params[:page_population])
  end

  def filter_helper(filtered_cases, response_columns)
    filtered_cases.map { |casex| { **(casex.payment_information ? casex.payment_information.as_json : {}), **casex.as_json, "payment_initialized" => casex.payment_initialized }.select { |k| [*response_columns, :payment_initialized].map { |r| r.to_s }.include?(k) } }
  end

  def filter
    case_params = filter_params[:match_columns].keys.map(&:to_s).filter { |p| [:case_no_or_parties, :record, :file_reference, :clients_reference, :client_id, :id, :title, :description].map(&:to_s).include?(p) }
    case_match_params = filter_params[:match_columns].select { |k| case_params.include?(k) }

    payment_information_params = filter_params[:match_columns].keys.map(&:to_s).filter { |p| [:total_fee, :outstanding, :paid_amount].map(&:to_s).include?(p) }
    payment_information_match_params = filter_params[:match_columns].select { |k| payment_information_params.include?(k) }

    response_columns = filter_params[:response_columns]

    if filter_params[:criteria] == "strict"
      if filter_params[:response] == "count"
        render json: { count: policy_scope(Case).where(case_match_params.as_json).count }
      else
        if filter_params[:page_number] && filter_params[:page_population]
          render json: filter_helper(policy_scope(Case).where(case_match_params.as_json).order("created_at DESC").paginate(page: filter_params[:page_number], per_page: filter_params[:page_population]), response_columns)
        else
          filtered_cases = []

          if (filter_params[:client_only])
            filtered_cases = policy_scope(Case).where({ **case_match_params.as_json, client_id: filter_params[:client_only][:client_and_id] }).order("created_at DESC")
          else
            filtered_cases = policy_scope(Case).where(case_match_params.as_json).order("created_at DESC")
          end

          matched_cases = []

          if payment_information_params.size > 0
            filtered_cases.filter { |pr| pr.payment_information != nil }.map { |pi| pi.payment_information.as_json }.each do |p|
              flag = true

              payment_information_match_params.each do |k, v|
                if p[k].to_f != v.to_f
                  flag = false
                  break
                end
              end

              if flag == true
                matched_cases << p["case_id"]
              end
            end
          end

          render json: filter_helper(filtered_cases.filter { |c| payment_information_params.size < 1 ? true : matched_cases.include?(c.id) }, response_columns)
        end
      end
    else
      case_sql = ""
      sql_values = []

      or_sql_params = case_match_params.as_json.select { |k| k != (!!filter_params[:client_only] ? "client_id" : "") }.map { |k, v| [k, v] }.reduce([[], []]) do |acc, curr|
        acc[0].push(curr[0])
        acc[1].push(curr[1])
        acc
      end

      if (filter_params[:client_only])
        sql = ["cases.client_id = ?"]
        sql_values << filter_params[:client_only][:client_and_id]

        sql << "(#{or_sql_params[0].map { |k| "cases.#{k}::text ILIKE ?" }.join(" OR ")})" unless !(or_sql_params[0].size > 0)
        sql_values << or_sql_params[1].map { |p| "%#{p}%" }

        case_sql = sql.join(" AND ")
      else
        case_sql << or_sql_params[0].map { |k| "cases.#{k}::text ILIKE ?" }.join(" OR ")
        sql_values << or_sql_params[1].map { |p| "%#{p}%" }
      end

      if filter_params[:response] == "count"
        render json: { count: policy_scope(Case).where(case_sql, *sql_values.flatten).count }
      else
        if filter_params[:page_number] && filter_params[:page_population]
          render json: filter_helper(policy_scope(Case).where(case_sql, *sql_values.flatten).order("created_at DESC").paginate(page: filter_params[:page_number], per_page: filter_params[:page_population]), response_columns)
        else
          filtered_cases = policy_scope(Case).where(case_sql, *sql_values.flatten).order("created_at DESC")

          matched_cases = []

          if payment_information_params.size > 0
            filtered_cases.filter { |pr| pr.payment_information != nil }.map { |pi| pi.payment_information.as_json }.each do |p|
              flag = false

              payment_information_match_params.each do |k, v|
                if p[k].to_s.include?(v.to_s)
                  flag = true
                  break
                end
              end

              if flag == true
                matched_cases << p["case_id"]
              end
            end
          end

          render json: filter_helper(filtered_cases.filter { |c| payment_information_params.size < 1 ? true : matched_cases.include?(c.id) }, response_columns)
        end
      end
    end
  end

  def range_filter
  
    range_filter_hash = filter_params[:per_column_range_filter_params]

    pp filter_params

    if not range_filter_hash or not range_filter_hash[:parameter] or not range_filter_hash[:parameter_range] or range_filter_hash[:parameter_range].size < 1
      render json: { error: "Unprocessable Entity" }, status: :unprocessable_entity
    else

      sql_tokens = []
      sql_values = []

      if params[:client_id]
        client = find_client()
        sql_tokens << "cases.client_id = ?"
        sql_values << client.id
      end

      sql_tokens << "cases.#{range_filter_hash[:parameter]} >= ?"
      sql_tokens << "cases.#{range_filter_hash[:parameter]} < ?"
      sql_values << range_filter_hash[:parameter_range]

      if filter_params[:response] == "count"
        render json: { count: policy_scope(Case).order("created_at DESC").where( sql_tokens.flatten.join(" AND "), *sql_values.flatten).count }
      else
        render json: policy_scope(Case).where( sql_tokens.flatten.join(" AND "), *sql_values.flatten).order("created_at DESC").paginate(page: filter_params[:page_number], per_page: filter_params[:page_population])
      end
    end
  end

  def show
    authorize @casex, :view?
    render json: @casex
  end

  def create
    authorize :create?
    cs = Case.create!(case_params)
    render json: cs, status: :created
  end

  def add_party
    # Clone party parameters
    pars = party_params

    # Remove case id from params
    pars.delete :id

    # Create Party
    party = Party.create!({
      **pars,
      case_id: @casex.id,
    })
    render json: @casex.parties, status: :created
  end

  def add_installment
    authorize
    if @casex.payment_information
      payment_information = @casex.payment_information
      installment = Payment.create!({
        payment_method: installment_params[:payment_method],
        payment_type: installment_params[:payment_type],
        amount: installment_params[:amount],
        payment_information_id: payment_information.id,
      })

      update_payment_information(payment_information, installment.amount)

      render json: payment_information, status: :accepted
    else
      raise UnauthorizedAccessException.new("Payment Information not found", 404)
    end
  end

  def create_payment_information
    if @casex.payment_information
      render json: { message: "Payment Information Exists. Consider performing an update" }, status: 409
    else
      if payment_information_params[:payment_type] == "full"
        payment_information = PaymentInformation.create!({
          case_id: @casex.id,
          payment_type: "full",
          outstanding: 0,
          paid_amount: payment_information_params[:total_fee],
          total_fee: payment_information_params[:total_fee],
        })
        render json: payment_information, status: :created
      else
        # Extract the down payment params
        down_payment_params = payment_information_params[:payment]

        # Create payment information
        payment_information = PaymentInformation.create!({
          case_id: @casex.id,
          payment_type: "installment",
          outstanding: payment_information_params[:total_fee].to_f,
          paid_amount: 0,
          total_fee: payment_information_params[:total_fee],
        })

        # Create first payment
        first_payment = Payment.create!({
          **down_payment_params,
          payment_information_id: payment_information.id,
        })

        update_payment_information(payment_information, first_payment.amount)

        render json: payment_information
      end
    end
  end

  def update_payment_information(payment_information, amount)
    # Update payment information balance
    payment_information.paid_amount = payment_information.paid_amount + amount
    payment_information.outstanding = payment_information.total_fee - payment_information.paid_amount

    # Resave payment information
    payment_information.save
  end

  def update
    @casex.update!(case_params)
    render json: @casex, status: :accepted
  end

  def payment_information
    render json: @casex.payment_information
  end

  def update_network_payment_information
    pay_info = @casex.payment_information
    pay_info.update!(update_payment_information_params)
    render json: pay_info
  end

  def case_documents
    render json: @casex.case_documents
  end

  def hearings
    render json: @casex.hearings
  end

  def important_dates
    render json: @casex.important_dates
  end

  def tasks
    render json: @casex.tasks
  end

  def parties
    render json: @casex.parties
  end

  def destroy
    authorize @casex, :destroy?
    @casex.destroy
    head :no_content
  end

  def destroy_multiple

    case_ids = bulk_destruction_ids[:case_ids]

    raise CustomException.new("Please provide atleast one case id", 400) unless case_ids and !case_ids.empty?

    # Authorize all cases before bulk destruction
    case_ids.each do |case_id|
      authorize Case.find(case_id), :destroy?
    end

    Case.destroy(case_ids)
    head :no_content
  end

  private

  def update_payment_information_params
    params.permit(:id, :total_fee, :payment_type, :outstanding, :paid_amount, :deposit_pay, :deposit_fees, :final_fees, :final_pay, :deposit)
  end

  def party_params
    params.permit(:id, :party_type, :name, :email, :contact_number, :address)
  end

  def case_params
    params.permit(:id, :title, :description, :case_no_or_parties, :record, :file_reference, :clients_reference, :status, :client_id, case_documents: [:title, :description, :file_attachment])
  end

  def payment_information_params
    params.permit(:id, :payment_type, :total_fee, payment: [:payment_type, :payment_method, :amount])
  end

  def installment_params
    params.permit(:id, :payment_type, :payment_method, :amount)
  end

  def set_case
    @casex = Case.find(params[:id])
  end

  def find_client
    client = Client.find_by(id: params[:client_id])
    if client
      client
    else
      raise ResourceNotFoundException, "Client by id #{params[:client_id]} not found"
    end
  end

  def bulk_destruction_ids
    params.permit(case_ids: [])
  end

  def filter_params
    params.permit(
      :page_number,
      :page_population,
      :criteria,
      :response,
      :client_id,
      per_column_range_filter_params: [:parameter, parameter_range: []],
      response_columns: [],
      client_only: [:client_and_id],
      match_columns: [
        :id,
        :title,
        :description,
        :client_id,
        :case_no_or_parties,
        :file_reference,
        :clients_reference,
        :record,
        :total_fee,
        :outstanding,
        :paid_amount,
      ],
    )
  end
end

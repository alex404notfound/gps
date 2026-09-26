import MapKit
import SwiftUI

struct LocationView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    @State private var mapPosition: MapCameraPosition = .automatic
    @State private var latitudeText = ""
    @State private var longitudeText = ""
    @State private var coordinateError: String?

    var body: some View {
        @Bindable var model = model

        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    connectionBanner
                    searchCard(searchQuery: $model.searchQuery)
                    mapCard
                    coordinateCard

                    if let selected = model.selectedCoordinate {
                        selectionCard(selected)
                    }

                    actionCard
                    savedPlacesCard
                }
                .padding(.horizontal, 18)
                .padding(.top, 12)
                .padding(.bottom, 32)
            }
            .background(Color(uiColor: .systemGroupedBackground))
            .navigationTitle("Location")
            .navigationBarTitleDisplayMode(.large)
            .onAppear(perform: syncCoordinateFields)
        }
    }

    private var connectionBanner: some View {
        HStack(spacing: 12) {
            Image(systemName: model.connectionState.isConnected ? "link.circle.fill" : "link.circle")
                .font(.title2)
                .foregroundStyle(model.connectionState.isConnected ? .green : .orange)

            VStack(alignment: .leading, spacing: 2) {
                Text(model.connectionState.title)
                    .font(.headline)
                Text(model.connectionState.isConnected
                     ? "Ready to change the reported location."
                     : "Connect in App Access to set a location.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .padding(16)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18))
        .accessibilityElement(children: .combine)
    }

    private func searchCard(searchQuery: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionTitle("Find a place", systemImage: "magnifyingglass")

            HStack(spacing: 10) {
                TextField("City, address, or landmark", text: searchQuery)
                    .textInputAutocapitalization(.words)
                    .autocorrectionDisabled()
                    .submitLabel(.search)
                    .onSubmit(search)
                    .accessibilityLabel("Search for a place")

                if model.isSearching {
                    ProgressView()
                        .controlSize(.small)
                        .accessibilityLabel("Searching")
                } else {
                    Button(action: search) {
                        Image(systemName: "arrow.right")
                            .font(.headline)
                            .frame(width: 32, height: 32)
                    }
                    .buttonStyle(.borderedProminent)
                    .clipShape(Circle())
                    .disabled(model.searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    .accessibilityLabel("Search")
                }
            }
            .padding(10)
            .background(Color(uiColor: .tertiarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 12))

            if !model.searchResults.isEmpty {
                Divider()
                ForEach(model.searchResults) { result in
                    Button {
                        choose(result)
                    } label: {
                        HStack(spacing: 12) {
                            Image(systemName: "mappin.circle.fill")
                                .font(.title3)
                                .foregroundStyle(.tint)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(result.name)
                                    .font(.subheadline.weight(.semibold))
                                    .foregroundStyle(.primary)
                                if !result.subtitle.isEmpty {
                                    Text(result.subtitle)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                        .lineLimit(2)
                                }
                            }
                            Spacer(minLength: 0)
                            Image(systemName: "chevron.right")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.tertiary)
                        }
                        .padding(.vertical, 5)
                    }
                    .buttonStyle(.plain)
                }
            }
        }
        .padding(16)
        .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 20))
    }

    private var mapCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                sectionTitle("Choose on the map", systemImage: "map")
                Spacer()
                Text("Tap to drop a pin")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            MapReader { proxy in
                Map(position: $mapPosition) {
                    if let selected = model.selectedCoordinate {
                        Marker(
                            model.selectedName.isEmpty ? "Selected" : model.selectedName,
                            coordinate: CLLocationCoordinate2D(
                                latitude: selected.latitude,
                                longitude: selected.longitude
                            )
                        )
                        .tint(.blue)
                    }

                    if let applied = model.lastAppliedCoordinate,
                       applied != model.selectedCoordinate {
                        Marker(
                            "Last accepted location",
                            systemImage: "checkmark.circle.fill",
                            coordinate: CLLocationCoordinate2D(
                                latitude: applied.latitude,
                                longitude: applied.longitude
                            )
                        )
                        .tint(.green)
                    }
                }
                .mapControls {
                    MapCompass()
                    MapScaleView()
                }
                .onTapGesture(coordinateSpace: .local) { point in
                    guard let mapCoordinate = proxy.convert(point, from: .local) else { return }
                    let coordinate = Coordinate(
                        latitude: mapCoordinate.latitude,
                        longitude: mapCoordinate.longitude
                    )
                    guard coordinate.isValid else { return }
                    model.select(coordinate, name: "Map pin")
                    syncCoordinateFields()
                    coordinateError = nil
                }
            }
            .frame(height: 280)
            .clipShape(RoundedRectangle(cornerRadius: 16))
            .accessibilityLabel("Map. Tap a location to select it.")
            .accessibilityHint("You can also use search or enter coordinates below.")
        }
        .padding(16)
        .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 20))
    }

    private var coordinateCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionTitle("Enter coordinates", systemImage: "location.north.line")

            if dynamicTypeSize.isAccessibilitySize {
                VStack(spacing: 10) {
                    coordinateField("Latitude", text: $latitudeText)
                    coordinateField("Longitude", text: $longitudeText)
                }
            } else {
                HStack(spacing: 10) {
                    coordinateField("Latitude", text: $latitudeText)
                    coordinateField("Longitude", text: $longitudeText)
                }
            }

            if let coordinateError {
                Label(coordinateError, systemImage: "exclamationmark.circle")
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            Button {
                selectEnteredCoordinate()
            } label: {
                Label("Use these coordinates", systemImage: "mappin.and.ellipse")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
        }
        .padding(16)
        .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 20))
    }

    private func coordinateField(_ title: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title)
                .font(.caption.weight(.medium))
                .foregroundStyle(.secondary)
            TextField("0.0", text: text)
                .keyboardType(.numbersAndPunctuation)
                .textContentType(.none)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .padding(10)
                .background(Color(uiColor: .tertiarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 10))
                .accessibilityLabel(title)
        }
        .frame(maxWidth: .infinity)
    }

    private func selectionCard(_ coordinate: Coordinate) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "mappin.circle.fill")
                    .font(.title2)
                    .foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 4) {
                    Text(model.selectedName.isEmpty ? "Selected location" : model.selectedName)
                        .font(.headline)
                    Text(coordinate.formatted)
                        .font(.subheadline.monospacedDigit())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                Spacer(minLength: 0)
            }

            Button {
                model.saveFavorite()
            } label: {
                Label("Save to favorites", systemImage: "star")
            }
            .buttonStyle(.bordered)
        }
        .padding(16)
        .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 20))
    }

    private var actionCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            sectionTitle("Location controls", systemImage: "location.circle")

            if let lastApplied = model.lastAppliedCoordinate {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Last accepted location")
                        .font(.subheadline.weight(.semibold))
                    Text(lastApplied.formatted)
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                    Text("Check another app to confirm the change.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else {
                Text("Set a location to see its last accepted value here.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            Text(model.monitorStatus)
                .font(.caption)
                .foregroundStyle(.secondary)
            if let notice = model.monitorAccessNotice {
                Label(notice, systemImage: "location.slash")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            if let source = model.reportedSourceStatus {
                Text(source)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if let readback = model.resetReadbackStatus {
                Text(readback)
                    .font(.caption.weight(.medium))
            }

            if dynamicTypeSize.isAccessibilitySize {
                VStack(spacing: 10) {
                    applyButton
                    resetButton
                }
            } else {
                HStack(spacing: 10) {
                    applyButton
                    resetButton
                }
            }

            if let message = operationMessage {
                Label(message, systemImage: operationFailed ? "exclamationmark.triangle" : "info.circle")
                    .font(.footnote)
                    .foregroundStyle(operationFailed ? .red : .secondary)
            }
        }
        .padding(16)
        .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 20))
    }

    private var savedPlacesCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionTitle("Favorites", systemImage: "star.fill")
            if model.favorites.isEmpty {
                Text("Save a selected place to find it here.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(model.favorites) { place in
                    HStack(spacing: 10) {
                        savedPlaceButton(place)
                        Button {
                            model.deleteFavorite(place.id)
                        } label: {
                            Image(systemName: "trash")
                                .foregroundStyle(.secondary)
                                .frame(width: 44, height: 44)
                                .contentShape(Rectangle())
                        }
                        .accessibilityLabel("Remove \(place.name) from favorites")
                    }
                }
            }

            if !model.recentPlaces.isEmpty {
                Divider()
                sectionTitle("Recent", systemImage: "clock.arrow.circlepath")
                ForEach(model.recentPlaces.prefix(5)) { place in
                    savedPlaceButton(place)
                }
            }
        }
        .padding(16)
        .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 20))
    }

    private func savedPlaceButton(_ place: SavedPlace) -> some View {
        Button {
            model.select(place)
            focus(on: place.coordinate)
            syncCoordinateFields()
            coordinateError = nil
        } label: {
            HStack(spacing: 10) {
                Image(systemName: "mappin")
                    .foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 3) {
                    Text(place.name)
                        .font(.subheadline.weight(.medium))
                        .foregroundStyle(.primary)
                    Text(place.coordinate.formatted)
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func sectionTitle(_ title: String, systemImage: String) -> some View {
        Label(title, systemImage: systemImage)
            .font(.headline)
    }

    private var applyButton: some View {
        Button {
            Task { await model.apply() }
        } label: {
            Label(applyTitle, systemImage: "location.fill")
                .frame(maxWidth: .infinity)
        }
        .buttonStyle(.borderedProminent)
        .disabled(model.selectedCoordinate == nil || !model.connectionState.isConnected || model.operationState.isBusy)
    }

    private var resetButton: some View {
        Button {
            Task { await model.reset() }
        } label: {
            Label(resetTitle, systemImage: "arrow.counterclockwise")
                .frame(maxWidth: .infinity)
        }
        .buttonStyle(.bordered)
        .disabled(!model.connectionState.isConnected || model.operationState.isBusy)
    }

    private var applyTitle: String {
        if case .applying = model.operationState { return "Setting…" }
        return "Set location"
    }

    private var resetTitle: String {
        if case .resetting = model.operationState { return "Resetting…" }
        return "Reset location"
    }

    private var operationFailed: Bool {
        if case .failed = model.operationState { return true }
        return false
    }

    private var operationMessage: String? {
        if case .failed(let message) = model.operationState {
            return model.statusMessage ?? message
        }
        guard let message = model.statusMessage else { return nil }
        if message.contains("command accepted") {
            // The accepted set state has its own short follow-up above. A reset
            // clears that state, so show the follow-up in the message row.
            return model.lastAppliedCoordinate == nil ? "Check another app to confirm the change." : nil
        }
        return message
    }

    private func search() {
        guard !model.searchQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        Task { await model.search() }
    }

    private func choose(_ result: SearchResult) {
        model.select(result)
        focus(on: result.coordinate)
        syncCoordinateFields()
        coordinateError = nil
    }

    private func selectEnteredCoordinate() {
        let latitude = Double(latitudeText.trimmingCharacters(in: .whitespacesAndNewlines))
        let longitude = Double(longitudeText.trimmingCharacters(in: .whitespacesAndNewlines))
        guard let latitude, let longitude else {
            coordinateError = "Enter a number for both latitude and longitude."
            return
        }
        let coordinate = Coordinate(latitude: latitude, longitude: longitude)
        guard coordinate.isValid else {
            coordinateError = "Latitude must be −90…90 and longitude −180…180."
            return
        }
        model.select(coordinate, name: "Custom coordinates")
        focus(on: coordinate)
        coordinateError = nil
    }

    private func syncCoordinateFields() {
        guard let coordinate = model.selectedCoordinate else { return }
        latitudeText = String(coordinate.latitude)
        longitudeText = String(coordinate.longitude)
        focus(on: coordinate)
    }

    private func focus(on coordinate: Coordinate) {
        withAnimation(.easeInOut(duration: 0.35)) {
            mapPosition = .region(MKCoordinateRegion(
                center: CLLocationCoordinate2D(latitude: coordinate.latitude, longitude: coordinate.longitude),
                span: MKCoordinateSpan(latitudeDelta: 0.025, longitudeDelta: 0.025)
            ))
        }
    }
}
